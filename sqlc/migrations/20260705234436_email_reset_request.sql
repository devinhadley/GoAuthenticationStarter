-- +goose Up

CREATE TABLE email_reset_requests (
  id bytea PRIMARY KEY CHECK (octet_length(id) = 32), -- SHA-256 of reset token
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  new_email CITEXT NOT NULL CHECK (char_length(new_email) BETWEEN 1 AND 320),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- +goose Down
DROP TABLE IF EXISTS email_reset_requests;
