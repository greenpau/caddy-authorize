package validate

import (
	"net/mail"
)

func ValidateLoginHint(loginHint string) bool {
	_, err := mail.ParseAddress(loginHint)
	return err == nil
}
