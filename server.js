import express from "express";
import { z } from "zod";
import { createRemoteJWKSet, jwtVerify, SignJWT } from "jose";
import { createClient } from "@supabase/supabase-js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

// ═════════════════════════ 환경 변수 ═════════════════════════
const env = process.env;
const list = (v, d = "") => (v ?? d).split(",").map((s) => s.trim()).filter(Boolean);

const PORT = env.PORT || 3000;
const PUBLIC_URL = (env.PUBLIC_URL || `http://localhost:${PORT}`).replace(/\/+$/, "");
const AUTH_ENABLED = env.AUTH_ENABLED === "true";

// Okta
const OKTA_ISSUER = (env.OKTA_ISSUER || "").replace(/\/+$/, "");
const OKTA_AUDIENCE = env.OKTA_AUDIENCE || "";
const REQUIRED_SCOPE = env.REQUIRED_SCOPE || "db.read";

// Supabase
const SUPABASE_URL = (env.SUPABASE_URL || "").replace(/\/+$/, "").replace(/\/rest\/v1$/, "");
const SUPABASE_SERVICE_ROLE_KEY = env.SUPABASE_SERVICE_ROLE_KEY || "";
const SUPABASE_ANON_KEY = env.SUPABASE_ANON_KEY || "";
const SUPABASE_JWT_SECRET = env.SUPABASE_JWT_SECRET || "";
// rls : 사용자별 JWT로 접속 → Supabase RLS가 직접 권한 통제 (권장)
// app : service_role 키로 접속 → MCP 서버 코드만 권한 통제
const DB_MODE = SUPABASE_JWT_SECRET && SUPABASE_ANON_KEY ? "rls" : "app";

// 권한 정책
const ALLOWED_TABLES = list(env.ALLOWED_TABLES, "customers,employees");
const TABLE_GROUPS = Object.fromEntries(
  list(env.TABLE_GROUPS, "customers:MCP-Sales,employees:MCP-HR").map((p) => p.split(":").map((s) => s.trim()))
);
const OWNER_COLUMN = env.OWNER_COLUMN || "owner_email";
const OWNER_FILTER_TABLES = list(env.OWNER_FILTER_TABLES, "customers");
const WRITE_SCOPE = env.WRITE_SCOPE || "db.write";
const WRITE_GROUP = env.WRITE_GROUP || "MCP-DB-Writers";
const ADMIN_GROUP = env.ADMIN_GROUP || "MCP-Admins";
// false 로 두면 앱 계층 검사를 끄고 DB(RLS) 단독 통제를 확인할 수 있음 (테스트용)
const APP_LAYER_CHECKS = env.APP_LAYER_CHECKS !== "false";

// ═════════════════════════ 시작 전 검증 ═════════════════════════
function fail(msg) {
  console.error(`[설정 오류] ${msg}`);
  process.exit(1);
}
if (!SUPABASE_URL) fail("SUPABASE_URL 이 필요합니다.");
if (DB_MODE === "app" && !SUPABASE_SERVICE_ROLE_KEY)
  fail("SUPABASE_SERVICE_ROLE_KEY 또는 (SUPABASE_ANON_KEY + SUPABASE_JWT_SECRET) 가 필요합니다.");
if (AUTH_ENABLED && (!OKTA_ISSUER || !OKTA_AUDIENCE))
  fail("AUTH_ENABLED=true 이면 OKTA_ISSUER / OKTA_AUDIENCE 가 필요합니다.");
if (ALLOWED_TABLES.length === 0) fail("ALLOWED_TABLES 가 비어 있습니다.");

const serviceClient = SUPABASE_SERVICE_ROLE_KEY
  ? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } })
  : null;
const jwtSecretKey = SUPABASE_JWT_SECRET ? new TextEncoder().encode(SUPABASE_JWT_SECRET) : null;

// ═════════════════════════ 사용자 컨텍스트 / 권한 계산 ═════════════════════════
function buildContext(payload) {
  if (!payload) {
    // 인증 비활성화(테스트) 모드: 모든 권한
    return {
      authenticated: false,
      email: "anonymous",
      uid: "anonymous",
      clientId: null,
      scopes: [REQUIRED_SCOPE, WRITE_SCOPE],
      groups: [...new Set([...Object.values(TABLE_GROUPS), WRITE_GROUP, ADMIN_GROUP])],
    };
  }
  const scopes = Array.isArray(payload.scp) ? payload.scp : String(payload.scp || "").split(" ").filter(Boolean);
  const groups = Array.isArray(payload.groups) ? payload.groups : payload.groups ? [payload.groups] : [];
  return {
    authenticated: true,
    email: payload.email || payload.sub,
    uid: payload.uid || payload.sub,
    clientId: payload.cid || null,
    scopes,
    groups,
  };
}

function permissionsOf(ctx) {
  return {
    readableTables: ALLOWED_TABLES.filter((t) => !TABLE_GROUPS[t] || ctx.groups.includes(TABLE_GROUPS[t])),
    canWrite: ctx.scopes.includes(WRITE_SCOPE) || ctx.groups.includes(WRITE_GROUP),
    isAdmin: ctx.groups.includes(ADMIN_GROUP),
  };
}

// 사용자별 Supabase 클라이언트 (rls 모드: Okta 신원을 담은 단기 JWT 발급)
async function dbFor(ctx) {
  if (DB_MODE === "app") return serviceClient;
  const token = await new SignJWT({
    role: "authenticated",
    email: ctx.email,
    app_groups: ctx.groups,
    app_scopes: ctx.scopes,
  })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setSubject(String(ctx.uid))
    .setAudience("authenticated")
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(jwtSecretKey);

  return createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    global: { headers: { Authorization: `Bearer ${token}` } },
  });
}

const ok = (obj) => ({ content: [{ type: "text", text: JSON.stringify(obj, null, 2) }] });
const deny = (msg) => ({ isError: true, content: [{ type: "text", text: msg }] });
const log = (ctx, msg) => console.log(`[${new Date().toISOString()}] user=${ctx.email} ${msg}`);

// ═════════════════════════ MCP 서버 (도구) ═════════════════════════
function buildMcpServer(ctx) {
  const server = new McpServer({ name: "okta-supabase-mcp", version: "2.0.0" });
  const perms = permissionsOf(ctx);

  // ── whoami : 인증 정보 + 계산된 권한
  server.tool("whoami", "현재 사용자의 Okta 신원, 그룹, 스코프와 그에 따른 권한을 보여줍니다.", {}, async () =>
    ok({
      user: ctx.email,
      uid: ctx.uid,
      client_id: ctx.clientId,
      scopes: ctx.scopes,
      groups: ctx.groups,
      permissions: {
        readable_tables: perms.readableTables,
        can_write: perms.canWrite,
        sees_all_rows: perms.isAdmin,
      },
      enforcement: {
        app_layer_checks: APP_LAYER_CHECKS,
        db_mode: DB_MODE === "rls" ? "rls (Supabase RLS가 함께 통제)" : "app (MCP 서버만 통제)",
      },
      auth_enabled: AUTH_ENABLED,
    })
  );

  // ── list_tables : 그룹 기준 조회 가능 테이블
  server.tool("list_tables", "현재 사용자가 조회할 수 있는 테이블 목록을 반환합니다.", {}, async () =>
    ok({
      readable_tables: perms.readableTables,
      all_tables: ALLOWED_TABLES,
      rule: TABLE_GROUPS,
    })
  );

  // ── query_table : 시나리오 2(그룹별 테이블) + 3(사용자별 데이터)
  server.tool(
    "query_table",
    "테이블을 조회합니다(읽기 전용). 테이블 접근은 Okta 그룹으로, customers 행은 담당자(owner_email) 기준으로 제한됩니다.",
    {
      table: z.enum(ALLOWED_TABLES).describe("조회할 테이블"),
      columns: z.string().default("*").describe("가져올 컬럼, 쉼표 구분 (기본 *)"),
      filter_column: z.string().optional().describe("필터 컬럼"),
      filter_value: z.string().optional().describe("필터 값 (정확히 일치)"),
      limit: z.number().int().min(1).max(100).default(20).describe("최대 행 수"),
    },
    async ({ table, columns, filter_column, filter_value, limit }) => {
      if (APP_LAYER_CHECKS && !perms.readableTables.includes(table)) {
        log(ctx, `DENY(app) query ${table}`);
        return deny(`[앱 계층 차단] '${table}' 테이블은 Okta 그룹 '${TABLE_GROUPS[table]}' 소속만 조회할 수 있습니다.`);
      }

      const db = await dbFor(ctx);
      let q = db.from(table).select(columns).limit(limit);
      const ownerScoped = OWNER_FILTER_TABLES.includes(table) && !perms.isAdmin;
      if (APP_LAYER_CHECKS && ownerScoped) q = q.eq(OWNER_COLUMN, ctx.email);
      if (filter_column && filter_value !== undefined) q = q.eq(filter_column, filter_value);

      const { data, error } = await q;
      if (error) {
        log(ctx, `ERROR query ${table}: ${error.message}`);
        return deny(`[DB 계층 차단 또는 오류] ${error.message}`);
      }
      log(ctx, `OK query ${table} rows=${data.length}`);
      return ok({
        table,
        row_count: data.length,
        scope: ownerScoped ? `본인 담당(${OWNER_COLUMN}=${ctx.email}) 데이터만` : "전체 데이터",
        note:
          DB_MODE === "rls" && data.length === 0
            ? "결과가 없다면 Supabase RLS 정책에 의해 보이지 않는 것일 수 있습니다."
            : undefined,
        rows: data,
      });
    }
  );

  // ── insert_customer : 시나리오 1(쓰기 권한)
  server.tool(
    "insert_customer",
    "customers 테이블에 고객을 추가합니다. 쓰기 권한(db.write 스코프 또는 MCP-DB-Writers 그룹)과 MCP-Sales 그룹이 필요합니다. 담당자는 요청한 사용자로 자동 지정됩니다.",
    {
      name: z.string().min(1).describe("고객 이름"),
      email: z.string().email().describe("고객 이메일"),
      plan: z.enum(["free", "pro", "enterprise"]).default("free").describe("요금제"),
    },
    async ({ name, email, plan }) => {
      if (APP_LAYER_CHECKS) {
        if (!perms.canWrite) {
          log(ctx, "DENY(app) insert_customer (no write)");
          return deny(`[앱 계층 차단] 쓰기 권한이 없습니다. '${WRITE_SCOPE}' 스코프 또는 Okta 그룹 '${WRITE_GROUP}' 이 필요합니다.`);
        }
        if (!perms.readableTables.includes("customers")) {
          log(ctx, "DENY(app) insert_customer (no table group)");
          return deny(`[앱 계층 차단] customers 테이블 권한이 없습니다. Okta 그룹 '${TABLE_GROUPS.customers}' 이 필요합니다.`);
        }
      }

      const db = await dbFor(ctx);
      const { data, error } = await db
        .from("customers")
        .insert({ name, email, plan, [OWNER_COLUMN]: ctx.email })
        .select();
      if (error) {
        log(ctx, `ERROR insert_customer: ${error.message}`);
        return deny(`[DB 계층 차단 또는 오류] ${error.message}`);
      }
      log(ctx, `OK insert_customer ${email}`);
      return ok({ inserted: data });
    }
  );

  return server;
}

// ═════════════════════════ Express 앱 ═════════════════════════
const app = express();
app.use(express.json({ limit: "1mb" }));

app.get("/", (_req, res) =>
  res.json({ status: "ok", auth: AUTH_ENABLED, db_mode: DB_MODE, app_layer_checks: APP_LAYER_CHECKS })
);

// OAuth Protected Resource Metadata
const resourceMetadata = (_req, res) =>
  res.json({
    resource: `${PUBLIC_URL}/mcp`,
    authorization_servers: [OKTA_ISSUER],
    scopes_supported: [REQUIRED_SCOPE, "offline_access"],
    bearer_methods_supported: ["header"],
  });
app.get("/.well-known/oauth-protected-resource", resourceMetadata);
app.get("/.well-known/oauth-protected-resource/mcp", resourceMetadata);

// Okta 연결 보조 (Claude가 메타데이터 조회에 실패해 /authorize, /token 으로 올 때)
let oktaMetaCache = null;
async function getOktaMetadata() {
  if (oktaMetaCache) return oktaMetaCache;
  const r = await fetch(`${OKTA_ISSUER}/.well-known/oauth-authorization-server`);
  if (!r.ok) throw new Error(`Okta 메타데이터 조회 실패: HTTP ${r.status}`);
  oktaMetaCache = await r.json();
  return oktaMetaCache;
}
app.get("/authorize", async (req, res) => {
  if (!OKTA_ISSUER) return res.status(404).send("Okta issuer not configured");
  try {
    const meta = await getOktaMetadata();
    const i = req.originalUrl.indexOf("?");
    res.redirect(302, `${meta.authorization_endpoint}${i >= 0 ? req.originalUrl.slice(i) : ""}`);
  } catch (e) {
    console.error(e);
    res.status(502).send("Okta 연결 실패");
  }
});
app.post("/token", express.urlencoded({ extended: false }), async (req, res) => {
  if (!OKTA_ISSUER) return res.status(404).json({ error: "not_configured" });
  try {
    const meta = await getOktaMetadata();
    const headers = { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" };
    if (req.headers.authorization) headers.Authorization = req.headers.authorization;
    const r = await fetch(meta.token_endpoint, { method: "POST", headers, body: new URLSearchParams(req.body).toString() });
    res.status(r.status).type(r.headers.get("content-type") || "application/json").send(await r.text());
  } catch (e) {
    console.error(e);
    res.status(502).json({ error: "okta_unreachable" });
  }
});

// Okta 토큰 검증
const JWKS = AUTH_ENABLED ? createRemoteJWKSet(new URL(`${OKTA_ISSUER}/v1/keys`)) : null;
function unauthorized(res, msg) {
  res.set(
    "WWW-Authenticate",
    `Bearer resource_metadata="${PUBLIC_URL}/.well-known/oauth-protected-resource", scope="${REQUIRED_SCOPE}"`
  );
  return res.status(401).json({ error: "unauthorized", message: msg });
}
async function requireAuth(req, res, next) {
  if (!AUTH_ENABLED) {
    req.ctx = buildContext(null);
    return next();
  }
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return unauthorized(res, "Bearer 토큰이 없습니다.");
  try {
    const { payload } = await jwtVerify(token, JWKS, { issuer: OKTA_ISSUER, audience: OKTA_AUDIENCE });
    const ctx = buildContext(payload);
    if (!ctx.scopes.includes(REQUIRED_SCOPE)) {
      return res.status(403).json({ error: "insufficient_scope", message: `${REQUIRED_SCOPE} 스코프가 필요합니다.` });
    }
    req.ctx = ctx;
    next();
  } catch (e) {
    return unauthorized(res, `토큰 검증 실패: ${e.message}`);
  }
}

// MCP 엔드포인트 (Streamable HTTP, stateless)
app.post("/mcp", requireAuth, async (req, res) => {
  try {
    const server = buildMcpServer(req.ctx);
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
const notAllowed = (_req, res) =>
  res.status(405).json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed" }, id: null });
app.get("/mcp", notAllowed);
app.delete("/mcp", notAllowed);

app.listen(PORT, () => {
  console.log(`MCP 서버 실행 중: ${PUBLIC_URL}/mcp (auth=${AUTH_ENABLED}, db_mode=${DB_MODE}, app_checks=${APP_LAYER_CHECKS})`);
  console.log(`테이블 권한: ${JSON.stringify(TABLE_GROUPS)} / 쓰기: ${WRITE_SCOPE} 또는 ${WRITE_GROUP} / 전체행: ${ADMIN_GROUP}`);
});
