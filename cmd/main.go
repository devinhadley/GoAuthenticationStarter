package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"devinhadley/gobootstrapweb/internal/db"
	"devinhadley/gobootstrapweb/internal/handlers"
	"devinhadley/gobootstrapweb/internal/middleware"
	"devinhadley/gobootstrapweb/internal/service/email"
	"devinhadley/gobootstrapweb/internal/service/session"
	"devinhadley/gobootstrapweb/internal/service/user"

	"github.com/jackc/pgx/v5/pgxpool"
)

func getEnvOrPanic(name string) string {
	value := os.Getenv(name)

	if value == "" {
		msg := fmt.Sprintf("missing required env var: %v", name)
		panic(msg)
	}

	return value
}

func main() {
	// Init connection to DB.
	dsn := getEnvOrPanic("DB_DSN")
	dbConPool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		log.Fatalf("Failed to init database connecton pool %v", err)
	}
	defer dbConPool.Close()

	queries := db.New(dbConPool)

	mux := http.NewServeMux()

	isProd := strings.ToLower(getEnvOrPanic("IS_PROD")) != "false"
	var mailService email.Service
	if isProd {
		log.Fatalf("no production email service configured.")
	} else {
		mailService = email.MailHogService{}
	}

	passwordResetURL := getEnvOrPanic("PASSWORD_RESET_URL")
	txnGenerator := user.CreateUserServiceTxnGenerator(dbConPool, queries)

	sessionService := session.NewService(queries)
	userService := user.NewService(queries, txnGenerator, mailService, sessionService, user.Config{PasswordResetURL: passwordResetURL})

	mux.Handle("POST /signup", handlers.CreateSignUpHandler(userService, sessionService))
	mux.Handle("POST /login", handlers.CreateLoginHandler(userService, sessionService))
	mux.Handle("POST /user/password-reset", handlers.CreateAuthenticatedPasswordResetHandler(userService))
	mux.Handle("POST /password-reset", handlers.CreatePasswordResetRequestHandler(userService))
	mux.Handle("PUT /password-reset", handlers.CreateTokenPasswordResetHandler(userService))

	muxWithMiddleware := middleware.CreateSessionMiddleware(userService, sessionService, mux)

	http.ListenAndServe(":8080", muxWithMiddleware)
}
