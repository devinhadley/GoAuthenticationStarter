package user

import (
	"bufio"
	"bytes"
	_ "embed"
	"strings"
)

//go:embed assets/pwdlist/100k-most-used-passwords-NCSC.txt
var commonPasswordsFile []byte

type commonPasswords map[string]struct{}

func (c commonPasswords) isCommonPassword(password string) bool {
	password = strings.ToLower(password)
	_, ok := c[password]
	return ok
}

func getCommonPasswords() commonPasswords {
	weakPasswordSet := make(map[string]struct{}, 100_000)

	scanner := bufio.NewScanner(bytes.NewReader(commonPasswordsFile))

	for scanner.Scan() {
		text := scanner.Text()
		text = strings.ToLower(text)

		weakPasswordSet[text] = struct{}{}
	}

	if err := scanner.Err(); err != nil {
		panic(err)
	}

	return weakPasswordSet
}
