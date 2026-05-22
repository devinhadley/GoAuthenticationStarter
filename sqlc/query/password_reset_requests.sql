-- name: CreatePasswordResetRequest :one
INSERT INTO password_reset_requests (
  id, user_id
) VALUES ( $1, $2 )
RETURNING *;
