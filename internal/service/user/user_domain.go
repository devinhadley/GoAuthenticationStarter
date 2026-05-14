package user

import (
	"devinhadley/gobootstrapweb/internal/db"
)

type User struct {
	raw db.User
}

func UserFromDB(dbUser db.User) User {
	return User{raw: dbUser}
}

func (u User) DBUser() db.User {
	return u.raw
}
