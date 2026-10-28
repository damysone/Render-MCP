import express from "express";
import { z } from "zod";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { createClient } from "@supabase/supabase-js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

// ───────────── 환경 변수 ─────────────
const PORT = process.env.PORT || 3000;
const PUBLIC_URL = (process.env.PUBLIC_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
const AUTH_ENABLED = process.env.AUTH_ENABLED === "true";

const OKTA_ISSUER = (process.env.OKTA_ISSUER || "").replace(/\/$/, ""); // 예: https://xxx.okta.com/oauth2/default
const OKTA_AUDIENCE = process.env.OKTA_AUDIENCE || "";                  // 예: api://my-mcp-server
const REQUIRED_SCOPE = process.env.REQUIRED_SCOPE || "db.read";

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ALLOWED_TABLES = (process.env.ALLOWED_TABLES || "customers")
  .split(",").map((t) => t.trim()).filter(Boolean);

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error("SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY 환경 변수가 필요합니다.");
  process.exit(1);
}
if (AUTH_ENABLED && (!OKTA_ISSUER || !OKTA_AUDIENCE)) {
  console.error("AUTH_ENABLED=true 이면 OKTA_ISSUER / OKTA_AUDIENCE 가 필요합니다.");
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, {
  auth: { persistSession: false },
});

// ───────────── MCP 서버 (도구 정의) ─────────────
function buildMcpServer(user) {
  const server = new McpServer({ name: "okta-supabase-mcp", version: "1.0.0" });

  // 도구 1: 조회 가능한 테이블 목록
  server.tool(
    "list_tables",
    "조회가 허용된 Supabase 테이블 목록을 반환합니다.",
    {},
    async () => ({
      content: [{ type: "text", text: JSON.stringify({ tables: ALLOWED_TABLES }, null, 2) }],
    })
  );

  // 도구 2: 테이블 조회 (읽기 전용)
  server.tool(
    "query_table",
    "허용된 Supabase 테이블에서 데이터를 조회합니다(읽기 전용). 선택적으로 한 컬럼에 대해 일치 필터를 걸 수 있습니다.",
    {
      table: z.enum(ALLOWED_TABLES).describe("조회할 테이블 이름"),
      columns: z.string().default("*").describe("가져올 컬럼, 쉼표로 구분 (기본: *)"),
      filter_column: z.string().optional().describe("필터할 컬럼 이름"),
      filter_value: z.string().optional().describe("필터 값 (정확히 일치)"),
      limit: z.number().int().min(1).max(100).default(20).describe("최대 행 수 (1~100)"),
    },
    async ({ table, columns, filter_column, filter_value, limit }) => {
      let q = supabase.from(table).select(columns).limit(limit);
      if (filter_column && filter_value !== undefined) q = q.eq(filter_column, filter_value);

      const { data, error } = await q;
      if (error) {
        return { isError: true, content: [{ type: "text", text: `조회 오류: ${error.message}` }] };
      }
      console.log(`[query] user=${user?.sub ?? "anonymous"} table=${table} rows=${data.length}`);
      return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
    }
  );

  // 도구 3: 현재 인증된 사용자 정보 (Okta 연동 확인용)
  server.tool(
    "whoami",
    "MCP 서버가 인식한 현재 사용자(Okta 토큰 정보)를 반환합니다.",
    {},
    async () => ({
      content: [{
        type: "text",
        text: JSON.stringify(
          user
            ? { sub: user.sub, uid: user.uid, scopes: user.scp, client_id: user.cid }
            : { message: "인증 비활성화 상태 (AUTH_ENABLED=false)" },
          null, 2
        ),
      }],
    })
  );

  return server;
}

// ───────────── Express 앱 ─────────────
const app = express();
app.use(express.json({ limit: "1mb" }));

// 헬스 체크
app.get("/", (_req, res) => res.json({ status: "ok", auth: AUTH_ENABLED }));

// OAuth Protected Resource Metadata (Claude가 Okta 인증 서버를 찾는 데 사용)
const resourceMetadata = (_req, res) =>
  res.json({
    resource: `${PUBLIC_URL}/mcp`,
    authorization_servers: [OKTA_ISSUER],
    scopes_supported: [REQUIRED_SCOPE, "offline_access"],
    bearer_methods_supported: ["header"],
  });
app.get("/.well-known/oauth-protected-resource", resourceMetadata);
app.get("/.well-known/oauth-protected-resource/mcp", resourceMetadata);

// Okta 토큰 검증 미들웨어
const JWKS = AUTH_ENABLED ? createRemoteJWKSet(new URL(`${OKTA_ISSUER}/v1/keys`)) : null;

function unauthorized(res, msg) {
  res.set(
    "WWW-Authenticate",
    `Bearer resource_metadata="${PUBLIC_URL}/.well-known/oauth-protected-resource", scope="${REQUIRED_SCOPE}"`
  );
  return res.status(401).json({ error: "unauthorized", message: msg });
}

async function requireAuth(req, res, next) {
  if (!AUTH_ENABLED) return next();

  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return unauthorized(res, "Bearer 토큰이 없습니다.");

  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: OKTA_ISSUER,
      audience: OKTA_AUDIENCE,
    });
    const scopes = Array.isArray(payload.scp) ? payload.scp : String(payload.scp || "").split(" ");
    if (!scopes.includes(REQUIRED_SCOPE)) {
      return res.status(403).json({ error: "insufficient_scope", message: `${REQUIRED_SCOPE} 스코프가 필요합니다.` });
    }
    req.user = payload;
    next();
  } catch (e) {
    return unauthorized(res, `토큰 검증 실패: ${e.message}`);
  }
}

// MCP 엔드포인트 (Streamable HTTP, stateless)
app.post("/mcp", requireAuth, async (req, res) => {
  try {
    const server = buildMcpServer(req.user);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => {
      transport.close();
      server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (e) {
    console.error("MCP 처리 오류:", e);
    if (!res.headersSent) {
      res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: null });
    }
  }
});

// stateless 모드에서는 GET/DELETE 미사용
const notAllowed = (_req, res) =>
  res.status(405).json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed" }, id: null });
app.get("/mcp", notAllowed);
app.delete("/mcp", notAllowed);

app.listen(PORT, () => {
  console.log(`MCP 서버 실행 중: ${PUBLIC_URL}/mcp (auth=${AUTH_ENABLED})`);
});
