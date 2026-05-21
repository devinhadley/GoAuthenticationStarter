-- name: CreatePasswordResetRequest :one
INSERT INTO password_reset_request (
  id, user_id
) VALUES ( $1, $2 )
RETURNING *;
