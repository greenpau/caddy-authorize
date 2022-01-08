package validate

import "testing"

func TestLoginHint(t *testing.T) {
	t.Run("returns true if given login_hint is a valid email", func(t *testing.T) {
		loginHint := "foo@bar.com"

		valid := ValidateLoginHint(loginHint)

		if !valid {
			t.Error("login hint should have been valid, was invalid")
		}
	})

	t.Run("returns false if given login_hint is an malformed email address", func(t *testing.T) {
		loginHint := "foo@"

		valid := ValidateLoginHint(loginHint)

		if valid {
			t.Error("login hint should have been invalid for an invalid email, was valid")
		}
	})

	t.Run("returns false if given login_hint has an invalid domain", func(t *testing.T) {
		loginHint := "foo@().com"

		valid := ValidateLoginHint(loginHint)

		if valid {
			t.Error("login hint should have been invalid for an invalid domain, was valid")
		}
	})
}
