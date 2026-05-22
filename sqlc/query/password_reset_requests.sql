-- name: CreatePasswordResetRequest :one
INSERT INTO password_reset_requests (
  id, user_id
) VALUES ( $1, $2 )
RETURNING *;

-- name: GetPasswordResetRequestByID :one
SELECT *
FROM password_reset_requests
WHERE id = $1;

-- name: DeletePasswordResetRequestByID :exec
DELETE FROM password_reset_requests
WHERE id = $1;
