# 🔒 커밋 전 마스킹 체크리스트

> 이 저장소는 **Public**입니다. 한 번 커밋된 정보는 파일을 지워도 히스토리에 남습니다.
> 원본 자료는 `_raw/` 폴더에 두면 `.gitignore`로 커밋에서 제외됩니다.

## 치환 규칙

| 원본 | 치환값 |
|---|---|
| Management 계정 ID | `111111111111` |
| Security 계정 ID | `222222222222` |
| Workload 계정 ID | `333333333333` |
| 기타 계정 ID | `444444444444` |
| 인스턴스 ID | `i-0123456789abcdef0` |
| Organization ID | `o-xxxxxxxxxx` |
| 공인 IP | `203.0.113.x` (문서용 예약 대역) |
| 팀원 이름 · IAM 사용자명 | `member-a`, `member-b` … |

## 커밋 전 확인

- [ ] 계정 ID (12자리 숫자)
- [ ] ARN · 인스턴스 ID · Organization ID
- [ ] 공인 IP · 사설 IP
- [ ] SSO 포털 URL · 콘솔 로그인 URL
- [ ] Discord 웹훅 URL · API 키 · 토큰
- [ ] 팀원 실명 · 연락처 · 이메일
- [ ] 스크린샷 속 계정 ID · IP (모자이크)

## 빠른 검사

```bash
# 12자리 숫자 (계정 ID 후보)
grep -rnE '\b[0-9]{12}\b' --exclude-dir=.git .

# 웹훅 · 키 · 포털 URL
grep -rniE 'discord(app)?\.com/api/webhooks|AKIA[0-9A-Z]{16}|awsapps\.com|signin\.aws' --exclude-dir=.git .
```
