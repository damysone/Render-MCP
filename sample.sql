-- Supabase SQL Editor에서 실행: 테스트용 샘플 테이블
create table if not exists public.customers (
  id bigint generated always as identity primary key,
  name text not null,
  email text not null,
  plan text not null default 'free',
  created_at timestamptz not null default now()
);

alter table public.customers enable row level security;

insert into public.customers (name, email, plan) values
  ('김민수', 'minsu@example.com', 'pro'),
  ('이지은', 'jieun@example.com', 'free'),
  ('박서준', 'seojun@example.com', 'enterprise'),
  ('최유나', 'yuna@example.com', 'pro'),
  ('정도윤', 'doyun@example.com', 'free');
