package user

import "devinhadley/gobootstrapweb/internal/db"

type User struct {
	db.User
}

func userFromDB(dbUser db.User) User {
	return User{User: dbUser}
}
