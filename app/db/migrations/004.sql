-- Migration 004: Mail Settings Table
create table if not exists mail_settings (
    dummy_id integer unique default 1 check (dummy_id = 1),
    enabled boolean not null default false,
    host text,
    port integer,
    username text,
    password text,
    encryption text not null default 'tls',
    sender text,
    notify_on_account_creation boolean not null default true,
    warn_before_cert_expires_days integer default 20,
    notify_when_cert_expired boolean not null default true,
    updated_at timestamptz not null default now(),
    primary key (dummy_id)
);
