-- name: CreateSession :one
INSERT INTO sessions (
    id,
    user_id
) VALUES (
    $1,
    $2
)
RETURNING *;

-- name: GetActiveSession :one
SELECT s.*
FROM sessions s
JOIN users u on s.user_id = u.id 
WHERE s.id = $1 AND s.is_active = TRUE and u.is_active = TRUE;

-- name: DeactivateSession :exec
UPDATE sessions
SET is_active = FALSE
WHERE id = $1 and is_active = TRUE;

-- name: GetSessionCountByUser :one
SELECT COUNT(*)
FROM sessions
WHERE user_id = $1 and is_active = TRUE;

-- name: UpdateSessionIDAndRefreshedAt :one
UPDATE sessions
SET id = $2, last_refreshed_at = NOW()
WHERE id = $1 and is_active = TRUE
RETURNING *;

-- name: UpdateSessionLastSeenToNow :one
UPDATE sessions
SET last_seen_at = NOW()
WHERE id = $1 and is_active = TRUE
RETURNING *;

-- name: DeactivateLeastRecentlyUsedSessionForUser :exec
UPDATE sessions
SET is_active = FALSE
WHERE id = (
  SELECT s.id
  FROM sessions s
  WHERE s.user_id = $1 and is_active = TRUE
  ORDER BY s.last_seen_at ASC
  LIMIT 1
);

