CREATE TABLE users (
    id BIGINT PRIMARY KEY DEFAULT ('x' || lpad(encode(gen_random_bytes(7), 'hex'), 16, '0'))::bit(64)::bigint,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL
);
