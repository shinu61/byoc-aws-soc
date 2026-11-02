const AWS_OPERATION_TIMEOUT_MS = 5_000;

const DISCORD_ACK_TIMEOUT_MS = 1_800;

const DISCORD_OPERATION_TIMEOUT_MS = 5_000;

const DISCORD_API = "https://discord.com/api/v10";

const USER_AGENT = "SOC-Discord-Approval/1.0";

const RUNBOOK_DECISIONS = {

  R2: new Set(["APPROVED", "FALSE_POSITIVE", "REJECTED"]),

  R3: new Set(["APPROVED", "ALLOWED_ACTIVITY", "FALSE_POSITIVE"]),

  R4: new Set(["APPROVED", "ALLOWED_ACTIVITY", "FALSE_POSITIVE"]),

  R5: new Set(["APPROVED", "ALLOWED_ACTIVITY", "FALSE_POSITIVE"]),

};

const loadDynamoSdk = async () => {

  const [client, document] = await Promise.all([

    import("@aws-sdk/client-dynamodb"),

    import("@aws-sdk/lib-dynamodb"),

  ]);

  return { ...client, ...document };

};

const loadStepFunctionsSdk = () => import("@aws-sdk/client-sfn");
const loadLambdaSdk = () => import("@aws-sdk/client-lambda");
const R4_CRITICAL_INVOKE_TIMEOUT_MS = 10_000;

const tableName = () => {

  const name = (process.env.APPROVAL_TABLE_NAME ?? "").trim();

  if (!/^[A-Za-z0-9_.-]{3,255}$/.test(name)) {

    throw new Error("Configure APPROVAL_TABLE_NAME");

  }

  return name;

};

const requireString = (value) => {

  if (typeof value !== "string" || !value) throw new Error("Invalid approval metadata");

  return value;

};

const epochSeconds = (value) => {

  if (!Number.isSafeInteger(value) || value <= 0) throw new Error("Invalid approval time");

  return value;

};

export function createAwsAdapters({

  fetchImpl = globalThis.fetch,

  loadDynamo = loadDynamoSdk,

  loadStepFunctions = loadStepFunctionsSdk,
  loadLambda = loadLambdaSdk,

} = {}) {

  let dynamoPromise;

  let stepFunctionsPromise;
  let lambdaPromise;

  const dynamo = () => {

    if (!dynamoPromise) {

      dynamoPromise = loadDynamo().then((sdk) => ({

        sdk,

        client: sdk.DynamoDBDocumentClient.from(

          new sdk.DynamoDBClient({ maxAttempts: 1 }),

          { marshallOptions: { removeUndefinedValues: true } },

        ),

      })).catch((error) => {

        dynamoPromise = undefined;

        throw error;

      });

    }

    return dynamoPromise;

  };

  const stepFunctions = () => {

    if (!stepFunctionsPromise) {

      stepFunctionsPromise = loadStepFunctions().then((sdk) => ({

        sdk,

        client: new sdk.SFNClient({ maxAttempts: 1 }),

      })).catch((error) => {

        stepFunctionsPromise = undefined;

        throw error;

      });

    }

    return stepFunctionsPromise;

  };

  const lambda = () => {
    if (!lambdaPromise) {
      lambdaPromise = loadLambda().then((sdk) => ({
        sdk, client: new sdk.LambdaClient({ maxAttempts: 1 }),
      })).catch((error) => {
        lambdaPromise = undefined;
        throw error;
      });
    }
    return lambdaPromise;
  };

  const sendDynamo = async (Command, input, client) => client.send(

    new Command(input),

    { abortSignal: AbortSignal.timeout(AWS_OPERATION_TIMEOUT_MS) },

  );

  const store = {

    async get(approvalId) {

      const name = tableName();

      requireString(approvalId);

      const { sdk, client } = await dynamo();

      const result = await sendDynamo(sdk.GetCommand, {

        TableName: name,

        Key: { approval_id: approvalId },

        ConsistentRead: true,

      }, client);

      return result.Item;

    },

    async claim({ record, decision, userId, interactionId, now }) {

      const name = tableName();

      epochSeconds(now);

      if (!["PENDING", "CALLBACK_RETRY"].includes(record?.status)

          || !Object.hasOwn(RUNBOOK_DECISIONS, record?.runbook_id)

          || !RUNBOOK_DECISIONS[record.runbook_id].has(decision)) {

        throw new Error("Invalid approval claim");

      }

      const names = {

        "#status": "status",

        "#expires": "expires_at",

        "#runbook": "runbook_id",

        "#channel": "channel_id",

        "#message": "message_id",

        "#token": "task_token",

        "#finding": "finding_id",

        "#owner": "claim_owner",

        "#updated": "updated_at",

        "#decision": "decision",

        "#output": "callback_output",

        "#error": "callback_error_code",

      };

      const values = {

        ":expected_status": record.status,

        ":pending": "CALLBACK_PENDING",

        ":now": now,

        ":runbook": record.runbook_id,

        ":channel": requireString(record.channel_id),

        ":message": requireString(record.message_id),

        ":token": requireString(record.task_token),

        ":finding": requireString(record.finding_id),

        ":owner": requireString(interactionId),

        ":decision": decision,

      };

      let condition = "#status = :expected_status AND #expires > :now"

        + " AND #runbook = :runbook AND #channel = :channel AND #message = :message"

        + " AND #token = :token AND #finding = :finding";

      let update = "SET #status = :pending, #owner = :owner, #updated = :now";

      if (record.status === "PENDING") {

        const decidedAt = new Date(now * 1_000).toISOString();

        names["#approver"] = "approver_user_id";

        names["#decided"] = "decided_at";

        values[":approver"] = requireString(userId);

        values[":decided"] = decidedAt;

        values[":output"] = JSON.stringify({

          approval_id: requireString(record.approval_id),

          finding_id: record.finding_id,

          runbook_id: record.runbook_id,

          decision,

          approver_user_id: userId,

          decided_at: decidedAt,

          action_performed: false,

        });

        update += ", #decision = :decision, #approver = :approver"

          + ", #decided = :decided, #output = :output";

      } else {

        if (record.decision !== decision) throw new Error("Approval decision is already fixed");

        values[":output"] = requireString(record.callback_output);

        condition += " AND #decision = :decision AND #output = :output";

      }

      update += " REMOVE #error";

      const { sdk, client } = await dynamo();

      const result = await sendDynamo(sdk.UpdateCommand, {

        TableName: name,

        Key: { approval_id: requireString(record.approval_id) },

        ConditionExpression: condition,

        UpdateExpression: update,

        ExpressionAttributeNames: names,

        ExpressionAttributeValues: values,

        ReturnValues: "ALL_NEW",

      }, client);

      if (!result.Attributes) throw new Error("Approval claim did not return a record");

      return result.Attributes;

    },

    async finish({ record, interactionId, status, now, removeToken = false, errorCode }) {

      const name = tableName();

      epochSeconds(now);

      if (!/^[A-Z_]{3,40}$/.test(status)

          || (removeToken && ["PENDING", "CALLBACK_PENDING", "CALLBACK_RETRY"].includes(status))) {

        throw new Error("Invalid approval completion");

      }

      const names = {

        "#status": "status",

        "#owner": "claim_owner",

        "#updated": "updated_at",

      };

      const values = {

        ":pending": "CALLBACK_PENDING",

        ":owner": requireString(interactionId),

        ":status": status,

        ":now": now,

      };

      let update = "SET #status = :status, #updated = :now";

      if (errorCode !== undefined) {

        if (typeof errorCode !== "string" || !/^[A-Za-z0-9_.-]{1,80}$/.test(errorCode)) {

          throw new Error("Invalid callback error code");

        }

        names["#error"] = "callback_error_code";

        values[":error"] = errorCode;

        update += ", #error = :error";

      }

      if (removeToken) {

        names["#token"] = "task_token";

        update += " REMOVE #token";

      }

      const { sdk, client } = await dynamo();

      const result = await sendDynamo(sdk.UpdateCommand, {

        TableName: name,

        Key: { approval_id: requireString(record.approval_id) },

        ConditionExpression: "#status = :pending AND #owner = :owner",

        UpdateExpression: update,

        ExpressionAttributeNames: names,

        ExpressionAttributeValues: values,

        ReturnValues: "ALL_NEW",

      }, client);

      return result.Attributes;

    },

  };

  const sendTaskSuccess = async (record) => {

    const { sdk, client } = await stepFunctions();

    await client.send(new sdk.SendTaskSuccessCommand({

      taskToken: requireString(record.task_token),

      output: requireString(record.callback_output),

    }), { abortSignal: AbortSignal.timeout(AWS_OPERATION_TIMEOUT_MS) });

  };

  const invokeCritical = async (interaction) => {
    const functionArn = (process.env.R4_CRITICAL_FUNCTION_ARN ?? "").trim();
    if (!/^arn:aws[a-z-]*:lambda:[a-z0-9-]+:\d{12}:function:R4_Critical_Function(?::[A-Za-z0-9_$-]+)?$/.test(functionArn)) {
      throw new Error("Configure R4_CRITICAL_FUNCTION_ARN");
    }
    const { sdk, client } = await lambda();
    const result = await client.send(new sdk.InvokeCommand({
      FunctionName: functionArn,
      InvocationType: "RequestResponse",
      Payload: Buffer.from(JSON.stringify({ mode: "interaction", interaction }), "utf8"),
    }), { abortSignal: AbortSignal.timeout(R4_CRITICAL_INVOKE_TIMEOUT_MS) });
    if (result.FunctionError || !result.Payload) throw new Error("R4 CRITICAL Lambda invocation failed");
    const decoded = JSON.parse(Buffer.from(result.Payload).toString("utf8"));
    if (!decoded || typeof decoded !== "object" || ![4, 7].includes(decoded.type)) {
      throw new Error("R4 CRITICAL Lambda returned unexpected output");
    }
    return decoded;
  };

  const discordRequest = async (path, method, payload, timeoutMs) => {

    let response;

    let signal;

    try {

      signal = AbortSignal.timeout(timeoutMs);

      response = await fetchImpl(`${DISCORD_API}${path}`, {

        method,

        headers: {

          "Content-Type": "application/json",

          Accept: "application/json",

          "User-Agent": USER_AGENT,

        },

        body: JSON.stringify(payload),

        signal,

      });

    } catch (caught) {

      const error = new Error("Discord request did not complete");

      error.name = "DiscordRequestError";

      error.transportCategory = signal?.aborted || ["AbortError", "TimeoutError"].includes(caught?.name)

        ? "timeout" : "network";

      throw error;

    }

    if (!response.ok) {

      const error = new Error("Discord rejected the request");

      error.name = "DiscordRequestError";

      error.httpStatus = response.status;

      throw error;

    }

    return { httpStatus: response.status };

  };

  const segment = (value) => encodeURIComponent(requireString(value));

  const webhookPath = (interaction) => "/webhooks/"

    + `${segment(interaction.application_id)}/${segment(interaction.token)}`;

  const discord = {

    ack(interaction) {

      return discordRequest(

        `/interactions/${segment(interaction.id)}/${segment(interaction.token)}/callback`,

        "POST", { type: 6 }, DISCORD_ACK_TIMEOUT_MS,

      );

    },

    update(interaction, payload) {

      return discordRequest(`${webhookPath(interaction)}/messages/@original`,

        "PATCH", payload, DISCORD_OPERATION_TIMEOUT_MS);

    },

    followup(interaction, content) {

      return discordRequest(webhookPath(interaction), "POST", {

        content: requireString(content),

        flags: 64,

        allowed_mentions: { parse: [] },

      }, DISCORD_OPERATION_TIMEOUT_MS);

    },

  };

  return { store, sendTaskSuccess, invokeCritical, discord };

}