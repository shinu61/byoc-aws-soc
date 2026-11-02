import { createHash, createPublicKey, verify } from "node:crypto";

import { performance } from "node:perf_hooks";

const reply = (statusCode, payload) => ({ statusCode,

  headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });

const notice = (content) => reply(200, {

  type: 4, data: { content, flags: 64, allowed_mentions: { parse: [] } },

});

const acknowledged = () => ({ statusCode: 202, body: "" });

const disabledButtons = (message) => (message.components ?? []).map((row) => ({

  ...row, components: (row.components ?? []).map((button) => ({ ...button, disabled: true })),

}));

const terminalStatuses = new Set(["APPROVED", "ALLOWED_ACTIVITY", "FALSE_POSITIVE", "REJECTED", "INVALID", "EXPIRED", "FAILED"]);

const decisions = {

  R2: { approve: "APPROVED", false_positive: "FALSE_POSITIVE", reject: "REJECTED" },

  R3: { approve: "APPROVED", allowed_activity: "ALLOWED_ACTIVITY", false_positive: "FALSE_POSITIVE" },

  R4: { approve: "APPROVED", allowed_activity: "ALLOWED_ACTIVITY", false_positive: "FALSE_POSITIVE" },

  R5: { approve: "APPROVED", allowed_activity: "ALLOWED_ACTIVITY", false_positive: "FALSE_POSITIVE" },

};

const completionLabels = {

  R2: { APPROVED: "차단 승인", FALSE_POSITIVE: "오탐 판정 기록", REJECTED: "거절" },

  R3: { APPROVED: "격리 승인", ALLOWED_ACTIVITY: "정상행위 기록", FALSE_POSITIVE: "오탐 판정 기록" },

  R4: { APPROVED: "격리 승인", ALLOWED_ACTIVITY: "정상행위 기록", FALSE_POSITIVE: "오탐 판정 기록" },

  R5: { APPROVED: "EC2 격리 승인", ALLOWED_ACTIVITY: "정상 행위 기록", FALSE_POSITIVE: "오탐 판정 기록" },

};

const retryableErrors = new Set([

  "AccessDeniedException", "AccessDenied", "ThrottlingException", "Throttling",

  "TooManyRequestsException", "KmsAccessDeniedException", "KmsInvalidStateException",

  "KmsThrottlingException", "InvalidOutput",

]);

const diagnosticErrorCodes = new Set([

  ...retryableErrors, "Error", "DiscordRequestError", "ConditionalCheckFailedException",

  "InvalidToken", "TaskDoesNotExist", "TaskTimedOut", "InternalServerError",

  "ResourceNotFoundException", "ValidationException", "ProvisionedThroughputExceededException",

  "RequestLimitExceeded", "AbortError", "TimeoutError", "TypeError", "NetworkingError",

  "CredentialsProviderError", "ServiceUnavailable", "ServiceUnavailableException",

]);

const diagnosticHttpStatus = (value) => Number.isInteger(value) && value >= 100 && value <= 599

  ? { http_status: value } : {};

const diagnosticError = (error) => ({

  error_code: diagnosticErrorCodes.has(error?.name) ? error.name : "OtherError",

  ...diagnosticHttpStatus(error?.httpStatus),

  ...(["timeout", "network"].includes(error?.transportCategory)

    ? { transport_category: error.transportCategory } : {}),

});

function validateRecord(record, interaction, approvalId, runbookId, decision, now) {

  if (!record) return "승인 요청을 찾을 수 없습니다. 새 알림을 확인해 주세요.";

  if (record.approval_id !== approvalId || record.runbook_id !== runbookId

      || !Object.hasOwn(decisions, record.runbook_id)

      || record.channel_id !== interaction.channel_id || record.message_id !== interaction.message?.id) {

    return "이 메시지와 연결된 승인 요청이 아닙니다.";

  }

  if (terminalStatuses.has(record.status)) return `이미 종료된 승인 요청입니다 (${record.status}).`;

  if (record.status === "CALLBACK_PENDING" || record.status === "CALLBACK_UNCERTAIN") {

    return "승인 결과를 처리 중이거나 실행 결과 확인이 필요합니다. 상태머신 실행 내역을 확인해 주세요.";

  }

  if (record.status !== "PENDING" && record.status !== "CALLBACK_RETRY") {

    return "아직 승인할 수 없는 요청입니다. 잠시 후 새 알림을 확인해 주세요.";

  }

  if (!Number.isSafeInteger(record.expires_at) || record.expires_at <= now) {

    return "승인 시간이 만료되었습니다. 새 상태머신 실행으로 확인해 주세요.";

  }

  if (typeof record.task_token !== "string" || !record.task_token

      || createHash("sha256").update(record.task_token).digest("hex").slice(0, 32) !== approvalId

      || typeof record.finding_id !== "string" || !record.finding_id

      || typeof record.execution_arn !== "string"

      || !/^arn:aws(?:-cn|-us-gov)?:states:[a-z0-9-]+:\d{12}:execution:[^:]+:.+$/.test(record.execution_arn)) {

    return "승인 요청의 실행 정보가 올바르지 않습니다.";

  }

  if (record.status === "CALLBACK_RETRY") {

    if (record.decision !== decision) return "이미 선택한 결정과 같은 버튼으로만 재시도할 수 있습니다.";

    try {

      const output = JSON.parse(record.callback_output);

      if (output.approval_id !== approvalId || output.finding_id !== record.finding_id

          || output.runbook_id !== record.runbook_id || output.decision !== decision

          || output.approver_user_id !== record.approver_user_id

          || output.decided_at !== record.decided_at || output.action_performed !== false) throw new Error();

    } catch {

      return "저장된 승인 결과를 확인해야 합니다. 상태머신 실행 내역을 확인해 주세요.";

    }

  }

  return null;

}

export function createHandler({ store, sendTaskSuccess, invokeCritical, discord, env = process.env,

  now = () => Date.now(), monotonicNow = () => performance.now(), log = () => {} }) {

  let firstInvocationInHandlerInstance = true;

  return async (event, context) => {

    const startedAt = monotonicNow();

    const firstInvocation = firstInvocationInHandlerInstance;

    firstInvocationInHandlerInstance = false;

    const awsRequestId = typeof context?.awsRequestId === "string"

      && /^[a-f\d]{8}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{12}$/i.test(context.awsRequestId)

      ? context.awsRequestId : undefined;

    const durationSince = (start) => Math.max(0, Math.round((monotonicNow() - start) * 1_000) / 1_000);

    const emit = (stage, outcome, details = {}) => {

      // Diagnostics contain only fixed fields and normalized metadata. Logging

      // failures must never change signature checks or approval processing.

      try {

        log({ diagnostic_build: "approval_ack_diagnostics_20261004",

          ...(awsRequestId ? { aws_request_id: awsRequestId } : {}),

          first_invocation_in_handler_instance: firstInvocation,

          stage, outcome, elapsed_ms: durationSince(startedAt), ...details });

      } catch {}

    };

    const measure = async (stage, operation) => {

      const operationStartedAt = monotonicNow();

      emit(stage, "started");

      try {

        const result = await operation();

        emit(stage, "succeeded", { duration_ms: durationSince(operationStartedAt),

          ...(stage.startsWith("discord_") ? diagnosticHttpStatus(result?.httpStatus) : {}) });

        return result;

      } catch (error) {

        emit(stage, "failed", { duration_ms: durationSince(operationStartedAt), ...diagnosticError(error) });

        throw error;

      }

    };

    const followup = async (interaction, content) => {

      try { await measure("discord_followup", () => discord.followup(interaction, content)); }

      catch {}

    };

    const update = async (interaction, content) => {

      try {

        await measure("discord_update", () => discord.update(interaction,

          { content, allowed_mentions: { parse: [] }, components: disabledButtons(interaction.message) }));

      } catch {

        await followup(interaction, `${content}\n원본 메시지 갱신에 실패했습니다.`);

      }

    };

    emit("handler", "started");

    try {

      const method = event?.requestContext?.http?.method ?? event?.httpMethod;

      if (method !== "POST") return reply(405, { error: "POST required" });

      if (typeof event.body !== "string") return reply(400, { error: "Missing body" });

      const publicKey = (env.DISCORD_PUBLIC_KEY ?? "").trim();

      if (!/^[a-f\d]{64}$/i.test(publicKey)) return reply(500, { error: "Configure DISCORD_PUBLIC_KEY" });

      const headers = Object.fromEntries(

        Object.entries(event.headers ?? {}).map(([key, value]) => [key.toLowerCase(), value]),

      );

      const signature = headers["x-signature-ed25519"] ?? "";

      const timestamp = headers["x-signature-timestamp"] ?? "";

      if (!/^[a-f\d]{128}$/i.test(signature) || !/^\d{10,12}$/.test(timestamp)

          || Math.abs(now() / 1000 - Number(timestamp)) > 300) return reply(401, { error: "Invalid signature" });

      const raw = Buffer.from(event.body, event.isBase64Encoded ? "base64" : "utf8");

      try {

        const key = createPublicKey({ key: Buffer.from("302a300506032b6570032100" + publicKey, "hex"),

          format: "der", type: "spki" });

        if (!verify(null, Buffer.concat([Buffer.from(timestamp), raw]), key, Buffer.from(signature, "hex"))) {

          return reply(401, { error: "Invalid signature" });

        }

      } catch { return reply(401, { error: "Invalid signature" }); }

      let interaction;

      try { interaction = JSON.parse(raw.toString("utf8")); }

      catch { return reply(400, { error: "Invalid JSON" }); }

      if (!interaction || typeof interaction !== "object" || Array.isArray(interaction)) {

        return reply(400, { error: "Invalid interaction" });

      }

      if (interaction.type === 1) return reply(200, { type: 1 });

      if (interaction.type !== 3) return notice("지원하지 않는 요청입니다.");

      // R4 CRITICAL supports Discord String Select (component_type=3) as well as buttons (2).
      // Route only after the same raw-body Ed25519 signature verification above.
      const customId = typeof interaction.data?.custom_id === "string" ? interaction.data.custom_id : "";
      const r4CriticalMatch = /^r4c:(select|approve|benign|fp):([a-f0-9]{32})$/.exec(customId);
      if (customId.startsWith("r4c:")) {
        if (!r4CriticalMatch) return notice("지원하지 않는 R4 CRITICAL 요청입니다.");
        const expectedComponentType = r4CriticalMatch[1] === "select" ? 3 : 2;
        if (interaction.data?.component_type !== expectedComponentType) {
          return notice("R4 CRITICAL 컴포넌트 유형이 올바르지 않습니다.");
        }

        const criticalAppId = (env.DISCORD_APPLICATION_ID ?? "").trim();
        const criticalChannelId = (env.R4_CRITICAL_CHANNEL_ID ?? env.DISCORD_CHANNEL_ID ?? "").trim();
        if (!criticalAppId || !criticalChannelId) {
          return notice("R4 CRITICAL Discord 앱/채널 환경변수를 설정해 주세요.");
        }
        if (interaction.application_id !== criticalAppId
          || interaction.channel_id !== criticalChannelId
          || interaction.message?.author?.id !== criticalAppId) {
          return notice("허용되지 않은 R4 CRITICAL 메시지입니다.");
        }
        if (!/^\d+$/.test(interaction.id ?? "")
          || typeof interaction.token !== "string" || !interaction.token
          || !interaction.message?.id) {
          return notice("R4 CRITICAL 요청 정보가 올바르지 않습니다.");
        }

        // ACK before DynamoDB/SFN/another Lambda: Discord requires a fast initial response.
        // The R4_Critical_Function independently authorizes Discord users/roles.
        try { await measure("discord_ack", () => discord.ack(interaction)); }
        catch { return reply(503, { error: "Unable to acknowledge interaction" }); }

        try {
          if (typeof invokeCritical !== "function") throw new Error("R4 Critical invoke adapter missing");
          const result = await measure("r4_critical_invoke", () => invokeCritical(interaction));
          if (result?.type === 4 && typeof result.data?.content === "string") {
            await followup(interaction, result.data.content);
          } else if (result?.type === 7 && typeof result.data?.content === "string"
            && Array.isArray(result.data?.components)) {
            // The critical Lambda returns the disabled original-message components.
            try { await measure("discord_update", () => discord.update(interaction, result.data)); }
            catch { await followup(interaction,
              "결정은 처리됐지만 Discord 메시지 갱신에 실패했습니다. 상태머신 실행 기록을 확인하세요."); }
          } else {
            await followup(interaction, "R4 CRITICAL 응답 형식이 올바르지 않습니다. 담당자에게 문의하세요.");
          }
        } catch {
          await followup(interaction, "R4 CRITICAL 처리에 실패했습니다. Lambda 로그와 Step Functions 실행을 확인하세요.");
        }
        return acknowledged();
      }

      // Legacy R2/R4 HIGH/R5 button handling below remains unchanged.
      if (interaction.data?.component_type !== 2) return notice("지원하지 않는 요청입니다.");

      const appId = (env.DISCORD_APPLICATION_ID ?? "").trim();

      const channelId = (env.DISCORD_CHANNEL_ID ?? "").trim();
      const allowedChannels = new Set([channelId, env.R4_CRITICAL_CHANNEL_ID,
        ...(env.DISCORD_EXTRA_APPROVAL_CHANNEL_IDS ?? "").split(",")]
        .map((value) => (value ?? "").trim()).filter(Boolean));

      const approvers = new Set((env.DISCORD_APPROVER_USER_IDS ?? "")

        .split(",").map((value) => value.trim()).filter(Boolean));

      if (!appId || !channelId || !approvers.size) return notice("승인 환경변수를 설정해 주세요.");

      if (interaction.application_id !== appId || !allowedChannels.has(interaction.channel_id)

          || interaction.message?.author?.id !== appId) return notice("허용된 앱과 채널의 메시지가 아닙니다.");

      const userId = interaction.member?.user?.id ?? interaction.user?.id;

      if (!approvers.has(userId)) return notice("승인 권한이 없습니다.");

      const mockActions = {

        "soc:r2:test:approve": "차단 승인",

        "soc:r2:test:false_positive": "오탐",

        "soc:r2:test:reject": "거절",

        "soc:r4:test:approve": "격리 승인",

        "soc:r4:test:allowed_activity": "정상행위",

        "soc:r4:test:false_positive": "오탐",

        "soc:r5:test:approve": "EC2 격리 승인",

        "soc:r5:test:allowed_activity": "정상 행위",

        "soc:r5:test:false_positive": "오탐",

      };

      const mockAction = Object.hasOwn(mockActions, customId) ? mockActions[customId] : null;

      const mockRunbook = customId.startsWith("soc:r5:") ? "R5"

        : customId.startsWith("soc:r4:") ? "R4" : "R2";

      if (mockAction) return reply(200, { type: 7, data: {

        content: `🧪 ${mockRunbook} ${mockAction} 버튼 수신 확인 · 모의 테스트입니다.`,

        allowed_mentions: { parse: [] }, components: disabledButtons(interaction.message),

      } });

      const match = /^soc:(r2|r3|r4|r5):approval:([a-f0-9]{32}):(approve|allowed_activity|false_positive|reject)$/.exec(customId);

      if (!match) return notice("지원하지 않는 버튼입니다.");

      const runbookId = match[1].toUpperCase();

      if (!Object.hasOwn(decisions[runbookId], match[3])) return notice("지원하지 않는 버튼입니다.");

      if (!/^\d+$/.test(interaction.id ?? "") || !interaction.token

          || typeof interaction.token !== "string" || !interaction.message?.id) return notice("버튼 요청 정보가 올바르지 않습니다.");

      // Discord's direct ACK precedes AWS calls. Every subsequent operation is

      // awaited in this invocation, so Lambda never freezes unfinished callbacks.

      try { await measure("discord_ack", () => discord.ack(interaction)); }

      catch {

        return reply(503, { error: "Unable to acknowledge interaction" });

      }

      const approvalId = match[2];

      const decision = decisions[runbookId][match[3]];

      let claimed;

      try {

        const record = await measure("approval_get", () => store.get(approvalId));

        const validation = validateRecord(record, interaction, approvalId, runbookId, decision, Math.floor(now() / 1000));

        if (validation) { await followup(interaction, validation); return acknowledged(); }

        claimed = await measure("approval_claim", () => store.claim({ record, decision, userId,

          interactionId: interaction.id, now: Math.floor(now() / 1000) }));

      } catch (error) {

        await followup(interaction, error?.name === "ConditionalCheckFailedException"

          ? "다른 요청이 먼저 처리했거나 승인 시간이 만료되었습니다."

          : "승인 저장소 조회 또는 결정 저장에 실패했습니다. API 권한과 설정을 확인해 주세요.");

        return acknowledged();

      }

      try { await measure("step_functions_callback", () => sendTaskSuccess(claimed)); }

      catch (error) {

        const errorCode = String(error?.name ?? "Error");

        const invalid = errorCode === "InvalidToken" || errorCode === "TaskDoesNotExist";

        const retryable = retryableErrors.has(errorCode);

        const status = invalid ? "INVALID" : retryable ? "CALLBACK_RETRY" : "CALLBACK_UNCERTAIN";

        let recorded = true;

        try {

          await measure("callback_error_record", () => store.finish({ record: claimed,

            interactionId: interaction.id, status, now: Math.floor(now() / 1000), removeToken: invalid, errorCode }));

        } catch { recorded = false; }

        const content = invalid

          ? "유효한 상태머신 실행 토큰이 아닙니다. Lambda 수동 테스트의 가짜 토큰으로는 승인할 수 없습니다. 실제 승인 대기 실행에서 발송한 새 알림을 사용해 주세요."

          : errorCode === "TaskTimedOut"

            ? "실행 토큰이 만료되었거나 요청이 이미 종료되었습니다. 상태머신 실행 내역에서 결과를 확인해 주세요."

            : retryable && recorded

              ? "상태머신에 결과 전달이 실패했습니다. API 권한과 설정을 확인한 뒤 같은 결정 버튼으로 재시도해 주세요."

              : "상태머신 결과 전달 여부를 확인해야 합니다. 상태머신 실행 내역을 확인해 주세요.";

        if (invalid && recorded) await update(interaction, `⚠️ ${runbookId} 승인 요청의 실행 토큰이 유효하지 않습니다.`);

        await followup(interaction, content);

        return acknowledged();

      }

      try {

        await measure("callback_completion_record", () => store.finish({ record: claimed,

          interactionId: interaction.id, status: claimed.decision, now: Math.floor(now() / 1000), removeToken: true }));

      } catch {

        await update(interaction, "⚠️ 상태머신에 결정 전달은 완료됐지만 승인 기록 갱신에 실패했습니다. 실행 내역을 확인해 주세요.");

        return acknowledged();

      }

      const action = completionLabels[runbookId][claimed.decision];

      await update(interaction, `✅ ${runbookId} ${action} 완료 · 상태머신에 결과를 전달했습니다.`);

      return acknowledged();

    } finally {

      emit("handler", "finished", { duration_ms: durationSince(startedAt) });

    }

  };

}
