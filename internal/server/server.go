package server

import (
	"net/http"

	"devinhadley/gobootstrapweb/internal/handlers"
	"devinhadley/gobootstrapweb/internal/middleware"
	"devinhadley/gobootstrapweb/internal/service/session"
	"devinhadley/gobootstrapweb/internal/service/user"
)

func NewMux(userService *user.Service, sessionService *session.Service) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("GET /user", handlers.CreateGetUserHandler())
	mux.Handle("POST /user/signup", handlers.CreateSignUpHandler(userService, sessionService))
	mux.Handle("POST /user/login", handlers.CreateLoginHandler(userService, sessionService))
	mux.Handle("PUT /user/password", handlers.CreateAuthenticatedPasswordResetHandler(userService))
	mux.Handle("POST /password-reset", handlers.CreatePasswordResetRequestHandler(userService))
	mux.Handle("PUT /password-reset", handlers.CreateTokenPasswordResetHandler(userService))

	return middleware.CreateSessionMiddleware(userService, sessionService, mux)
}
