create table users (
    id random_id not null,
    username text not null unique,
    password_hash text not null,
    created_at timestamptz not null default now(),
    last_login_at timestamptz default null,
    PRIMARY KEY (id)
);

create index users_username on users (username);
