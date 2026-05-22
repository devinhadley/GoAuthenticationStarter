package main

import (
	"context"
	"log"
	"net/http"
	"strings"

	"devinhadley/gobootstrapweb/internal/db"
	"devinhadley/gobootstrapweb/internal/email"
	"devinhadley/gobootstrapweb/internal/handlers"
	"devinhadley/gobootstrapweb/internal/service/session"
	"devinhadley/gobootstrapweb/internal/service/user"
	"devinhadley/gobootstrapweb/internal/utils"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	// Init connection to DB.
	dsn := utils.GetEnvOrExit("DB_DSN")
	dbConPool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		log.Fatalf("Failed to init database connecton pool %v", err)
	}
	defer dbConPool.Close()

	queries := db.New(dbConPool)

	mux := http.NewServeMux()

	isProd := strings.ToLower(utils.GetEnvOrExit("IS_PROD")) != "false"
	var mailService email.Service
	if isProd {
		log.Fatalf("no production email service configured.")
	} else {
		mailService = email.CreateMailHogService()
	}

	passwordResetURL := utils.GetEnvOrExit("PASSWORD_RESET_URL")

	userService := user.NewService(queries, mailService, user.Config{PasswordResetURL: passwordResetURL})
	sessionService := session.NewService(queries)

	mux.Handle("POST /signup", handlers.CreateSignUpHandler(userService, sessionService))
	mux.Handle("POST /login", handlers.CreateLoginHandler(userService, sessionService))
	mux.Handle("POST /password-reset", handlers.CreatePasswordResetRequestHandler(userService))

	http.ListenAndServe(":8080", mux)
}
