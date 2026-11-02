-- ═══════════════════════════════════════════════════════════
-- 시나리오 테스트용 Supabase 설정 (SQL Editor 에서 전체 실행)
-- ※ dklee@isd.co.kr 부분은 실제 테스트 사용자의 Okta 로그인(이메일)으로 바꿔주세요.
-- ═══════════════════════════════════════════════════════════

-- 1) customers 에 담당자 컬럼 추가 + 담당자 지정 (시나리오 3)
alter table public.customers add column if not exists owner_email text;
update public.customers set owner_email = 'dklee@isd.co.kr'     where id in (1, 2);
update public.customers set owner_email = 'other.user@isd.co.kr' where id in (3, 4, 5);

-- 2) employees 테이블 생성 (시나리오 2)
create table if not exists public.employees (
  id bigint generated always as identity primary key,
  name text not null,
  department text not null,
  title text not null,
  email text not null,
  created_at timestamptz not null default now()
);
alter table public.employees enable row level security;

insert into public.employees (name, department, title, email)
select * from (values
  ('한소희', '인사팀', '팀장',   'sohee@example.com'),
  ('강민호', '영업팀', '매니저', 'minho@example.com'),
  ('윤서연', '보안팀', '엔지니어', 'seoyeon@example.com'),
  ('오지훈', '개발팀', '리드',   'jihoon@example.com')
) as v(name, department, title, email)
where not exists (select 1 from public.employees);

-- 3) 권한 부여 (RLS 정책이 실제 통제)
grant select, insert on public.customers to authenticated;
grant select on public.employees to authenticated;

-- 4) 이전 테스트용 정책 정리
drop policy if exists "mcp read only" on public.customers;
drop policy if exists "mcp_customers_select" on public.customers;
drop policy if exists "mcp_customers_insert" on public.customers;
drop policy if exists "mcp_employees_select" on public.employees;

-- 5) RLS 정책 : MCP 서버가 넘겨주는 JWT 의 email / app_groups / app_scopes 로 판단

-- customers 조회: MCP-Sales 그룹 + (본인 담당 행 또는 MCP-Admins)
create policy "mcp_customers_select" on public.customers
for select to authenticated
using (
  (auth.jwt() -> 'app_groups') ? 'MCP-Sales'
  and (
    owner_email = auth.jwt() ->> 'email'
    or (auth.jwt() -> 'app_groups') ? 'MCP-Admins'
  )
);

-- customers 추가: MCP-Sales 그룹 + 쓰기 권한(db.write 또는 MCP-DB-Writers) + 담당자는 본인만
create policy "mcp_customers_insert" on public.customers
for insert to authenticated
with check (
  (auth.jwt() -> 'app_groups') ? 'MCP-Sales'
  and (
    (auth.jwt() -> 'app_groups') ? 'MCP-DB-Writers'
    or (auth.jwt() -> 'app_scopes') ? 'db.write'
  )
  and owner_email = auth.jwt() ->> 'email'
);

-- employees 조회: MCP-HR 그룹
create policy "mcp_employees_select" on public.employees
for select to authenticated
using ( (auth.jwt() -> 'app_groups') ? 'MCP-HR' );

-- 확인
select tablename, policyname, cmd from pg_policies where schemaname = 'public' order by tablename, policyname;
