# Okta + Supabase MCP 서버 (Render 배포용)

Claude 커스텀 커넥터에서 사용할 원격 MCP 서버입니다.
Streamable HTTP 방식이며, Okta 액세스 토큰 검증과 Supabase 읽기 전용 조회를 제공합니다.

## 제공 도구
- `list_tables` : 조회 가능한 테이블 목록
- `query_table` : 테이블 조회 (읽기 전용, 최대 100행)
- `whoami` : MCP 서버가 인식한 Okta 사용자/스코프 확인

## 1. Supabase 준비
1. Supabase SQL Editor에서 `sample.sql` 실행
2. Project Settings > API 에서 `Project URL`, `service_role` 키 복사

## 2. GitHub에 올리기
```bash
git init
git add .
git commit -m "init mcp server"
git branch -M main
git remote add origin https://github.com/<계정>/okta-mcp-server.git
git push -u origin main
```

## 3. Render 배포
1. Render > New > Web Service > GitHub 저장소 연결
2. Runtime: Node / Build Command: `npm install` / Start Command: `npm start`
3. Environment 에 `.env.example` 항목 입력 (처음엔 `AUTH_ENABLED=false`)
4. 배포 후 받은 주소를 `PUBLIC_URL` 에 넣고 재배포
5. `https://<서비스>.onrender.com/` 접속 시 `{"status":"ok"}` 나오면 성공

## 4. 1차 테스트 (인증 없이)
Claude 커스텀 커넥터에 `https://<서비스>.onrender.com/mcp` 등록 후
"customers 테이블 조회해줘" 라고 요청해 보세요.
※ 인증이 꺼진 동안은 URL을 아는 누구나 접근 가능하므로 샘플 데이터만 사용하세요.

## 5. 2차 테스트 (Okta 연동)
1. Okta Authorization Server 에 audience(`api://my-mcp-server`), 스코프(`db.read`), Access Policy 설정
2. Okta OIDC 앱(Web) 생성, Redirect URI 에 Claude 커넥터 콜백 주소 등록
3. Render 환경 변수 `AUTH_ENABLED=true`, `OKTA_ISSUER`, `OKTA_AUDIENCE` 설정 후 재배포
4. Claude 커넥터 고급 설정에 OIDC 앱의 Client ID / Secret 입력 후 연결
5. Claude에게 "whoami 실행해줘" 로 토큰 정보가 보이면 연동 성공

## 참고
- Render 무료 플랜은 유휴 시 잠들어 첫 요청이 느릴 수 있습니다.
- `service_role` 키는 RLS를 우회하므로 절대 코드/GitHub에 올리지 마세요(환경 변수로만).
