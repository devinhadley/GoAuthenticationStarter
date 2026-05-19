-- +goose Up

CREATE TABLE password_reset_request (
  id bytea PRIMARY KEY CHECK (octet_length(id) = 32), -- SHA-256 reset token
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- +goose Down
DROP TABLE IF EXISTS password_reset_request;
