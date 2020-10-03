package jwt

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwtlib "github.com/dgrijalva/jwt-go"
)

type AccessListTestInput struct {
	name       string
	action     string
	claim      string
	values     []string
	shouldFail bool // Whether test should result in a failure
	shouldErr  bool // Whether parsing of a response should result in error
	err        error
}

func evalAccessListTestResults(t *testing.T, i int, test AccessListTestInput, err error) (bool, error) {
	if !test.shouldErr && err != nil {
		return true, fmt.Errorf(
			"FAIL: Test %d, input (%v): expected success, received error: %v",
			i, test, err,
		)
	}
	if test.shouldFail && err == nil {
		return true, fmt.Errorf("FAIL: Test %d: input (%v):, expected failure but passed", i, test)
	}

	if err != nil {
		if test.err == nil {
			return true, fmt.Errorf(
				"FAIL: Test %d, input (%v): test missing error definition: %v",
				i, test, err,
			)
		}
		if test.err.Error() != err.Error() {
			return true, fmt.Errorf(
				"FAIL: Test %d, input (%v): expected different error: %s (expected) vs. %s (received)",
				i, test, test.err, err,
			)
		}
	}

	t.Logf("PASS: Test %d, input: %v", i, test)
	return false, nil
}

func TestAccessListEntry(t *testing.T) {
	testFailed := 0
	for i, test := range []AccessListTestInput{
		{
			name:       "allow anonymous role",
			action:     "allow",
			claim:      "roles",
			values:     []string{"anonymous"},
			shouldFail: false,
			shouldErr:  false,
			err:        nil,
		},
		{
			name:       "empty claim",
			action:     "allow",
			claim:      "",
			values:     []string{"anonymous"},
			shouldFail: false,
			shouldErr:  true,
			err:        ErrEmptyClaim,
		},
		{
			name:       "unsupported org claim",
			action:     "allow",
			claim:      "org",
			values:     []string{"contoso"},
			shouldFail: false,
			shouldErr:  true,
			err:        ErrUnsupportedClaim.WithArgs("org"),
		},
		{
			name:       "invalid action",
			action:     "foo",
			claim:      "roles",
			values:     []string{"anonymous"},
			shouldFail: false,
			shouldErr:  true,
			err:        ErrUnsupportedACLAction.WithArgs("foo"),
		},
		{
			name:       "empty action",
			action:     "",
			claim:      "roles",
			values:     []string{"anonymous"},
			shouldFail: false,
			shouldErr:  true,
			err:        ErrEmptyACLAction,
		},
		{
			name:       "empty claim value",
			action:     "allow",
			claim:      "roles",
			values:     []string{},
			shouldFail: false,
			shouldErr:  true,
			err:        ErrEmptyValue,
		},
	} {
		t.Logf("test: %d, %s", i, test.name)
		entry := NewAccessListEntry()

		abort, err := evalAccessListTestResults(t, i, test, entry.SetClaim(test.claim))
		if err != nil {
			t.Logf("%s", err)
			testFailed++
		}
		if abort {
			continue
		}

		abort, err = evalAccessListTestResults(t, i, test, entry.SetAction(test.action))
		if err != nil {
			t.Logf("%s", err)
			testFailed++
		}
		if abort {
			continue
		}

		abort, err = evalAccessListTestResults(t, i, test, entry.SetValue(test.values))
		if err != nil {
			t.Logf("%s", err)
			testFailed++
		}
		if abort {
			continue
		}

		if !test.shouldFail && !test.shouldErr {
			if err := entry.Validate(); err != nil {
				t.Logf("FAIL: Test %d, input (%v): %v", i, test, err)
				testFailed++
				continue
			}
		}

	}

	if testFailed > 0 {
		t.Fatalf("Failed %d tests", testFailed)
	}
}

func TestAccessList(t *testing.T) {
	testFailed := 0

	testPersonas := []struct {
		allow  bool
		claims *UserClaims
	}{
		{
			allow: false,
			claims: &UserClaims{
				ExpiresAt: time.Now().Add(time.Duration(900) * time.Second).Unix(),
				Name:      "Smith, John",
				Email:     "jsmith@contoso.com",
				Origin:    "localhost",
				Subject:   "jsmith@contoso.com",
				Roles:     []string{"guest"},
			},
		},
		{
			allow: false,
			claims: &UserClaims{
				ExpiresAt: time.Now().Add(time.Duration(900) * time.Second).Unix(),
				Name:      "Smith, Phil",
				Email:     "psmith@contoso.com",
				Origin:    "localhost",
				Subject:   "psmith@contoso.com",
				Roles:     []string{"admin", "guest"},
			},
		},
		{
			allow: true,
			claims: &UserClaims{
				ExpiresAt: time.Now().Add(time.Duration(900) * time.Second).Unix(),
				Name:      "Smith, Barry",
				Email:     "bsmith@contoso.com",
				Origin:    "localhost",
				Subject:   "bsmith@contoso.com",
				Roles:     []string{"admin"},
			},
		},
		{
			allow: false,
			claims: &UserClaims{
				ExpiresAt: time.Now().Add(time.Duration(900) * time.Second).Unix(),
				Name:      "Smith, Brent",
				Email:     "bsmith@contoso.com",
				Origin:    "localhost",
				Subject:   "bsmith@contoso.com",
				Roles:     []string{},
			},
		},
		{
			allow: false,
			claims: &UserClaims{
				ExpiresAt: time.Now().Add(time.Duration(900) * time.Second).Unix(),
				Name:      "Smith, Michael",
				Email:     "msmith@contoso.com",
				Origin:    "localhost",
				Subject:   "msmith@contoso.com",
				Roles:     []string{"editor"},
			},
		},
	}

	entry1 := NewAccessListEntry()
	if err := entry1.Validate(); err != nil {
		if err != ErrEmptyACLAction {
			t.Fatalf("error mismatch: %s (received) vs %s (expected)", err, ErrEmptyACLAction)
		}
	} else {
		t.Fatalf("expected error validating empty action")
	}
	entry1.Action = "foo bar"
	if err := entry1.Validate(); err != nil {
		if err.Error() != ErrUnsupportedACLAction.WithArgs("foo bar").Error() {
			t.Fatalf("error mismatch: %s (received) vs %s (expected)", err, ErrUnsupportedACLAction.WithArgs("foo bar"))
		}
	} else {
		t.Fatalf("expected error validating invalid action")
	}
	entry1.Allow()

	if err := entry1.Validate(); err != nil {
		if err.Error() != ErrEmptyACLClaim.Error() {
			t.Fatalf("error mismatch: %s (received) vs %s (expected)", err, ErrEmptyACLClaim)
		}
	} else {
		t.Fatalf("expected error validating invalid claim")
	}

	if err := entry1.SetClaim("roles"); err != nil {
		t.Fatalf("failed to set claim roles: %s", err)
	}

	if err := entry1.Validate(); err != nil {
		if err.Error() != ErrNoValues.Error() {
			t.Fatalf("error mismatch: %s (received) vs %s (expected)", err, ErrNoValues)
		}
	} else {
		t.Fatalf("expected error validating empty claim value")
	}

	if err := entry1.AddValue("guest"); err != nil {
		t.Fatalf("failed to set claim value: %s", err)
	}
	if err := entry1.AddValue("admin"); err != nil {
		t.Fatalf("failed to set claim value: %s", err)
	}

	t.Logf("Entry 1: %v", entry1)

	entry2 := NewAccessListEntry()
	entry2.Deny()
	if err := entry2.SetClaim("roles"); err != nil {
		t.Fatalf("failed to set claim roles: %s", err)
	}
	if err := entry2.AddValue(""); err == nil {
		t.Fatalf("expected error adding empty value")
	}
	if err := entry2.AddValue("guest"); err != nil {
		t.Fatalf("failed to set claim value: %s", err)
	}

	t.Logf("Entry 2: %v", entry2)

	entry3 := NewAccessListEntry()
	entry3.Deny()
	entry3.Claim = "org"
	if err := entry3.AddValue("contoso"); err != nil {
		t.Fatalf("failed to set claim value: %s", err)
	}

	t.Logf("Entry 3: %v", entry3)

	accessList := []*AccessListEntry{}
	accessList = append(accessList, entry1)
	accessList = append(accessList, entry2)
	accessList = append(accessList, entry3)

	for i, persona := range testPersonas {
		personaAllowed := false
		for _, entry := range accessList {
			claimAllowed, abortProcessing := entry.IsClaimAllowed(persona.claims)
			if abortProcessing {
				personaAllowed = claimAllowed
				break
			}
			if claimAllowed {
				personaAllowed = true
			}
		}
		if (personaAllowed && persona.allow) || (!personaAllowed && !persona.allow) {
			t.Logf("PASS: Persona %d %v is allowed: %t", i+1, persona.claims, personaAllowed)
			continue
		}

		t.Logf("FAIL: Persona %d %v is allowed: %t", i+1, persona.claims, personaAllowed)
		testFailed++
	}

	if testFailed > 0 {
		t.Fatalf("Failed %d tests", testFailed)
	}
}

func TestAuthorizeWithAccessList(t *testing.T) {
	testFailed := 0
	secret := "1234567890abcdef-ghijklmnopqrstuvwxyz"

	// Create access list with default deny that allows viewer only
	defaultDenyACL := []*AccessListEntry{
		&AccessListEntry{
			Action: "allow",
			Claim:  "roles",
			Values: []string{"viewer"},
		},
	}

	// Create access list with default allow that denies editor
	defaultAllowACL := []*AccessListEntry{
		&AccessListEntry{
			Action: "deny",
			Claim:  "roles",
			Values: []string{"editor"},
		},
		&AccessListEntry{
			Action: "allow",
			Claim:  "roles",
			Values: []string{"any"},
		},
	}

	// Create viewer persona
	viewer := jwtlib.MapClaims{
		"exp":    time.Now().Add(10 * time.Minute).Unix(),
		"iat":    time.Now().Add(10 * time.Minute * -1).Unix(),
		"nbf":    time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
		"name":   "Smith, John",
		"email":  "smithj@outlook.com",
		"origin": "localhost",
		"sub":    "smithj@outlook.com",
		"roles":  []string{"viewer"},
	}

	editor := jwtlib.MapClaims{
		"exp":    time.Now().Add(10 * time.Minute).Unix(),
		"iat":    time.Now().Add(10 * time.Minute * -1).Unix(),
		"nbf":    time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
		"name":   "Smith, Jane",
		"email":  "jane.smith@outlook.com",
		"origin": "localhost",
		"sub":    "jane.smith@outlook.com",
		"roles":  []string{"editor"},
	}

	tests := []struct {
		name      string
		claims    jwtlib.MapClaims
		acl       []*AccessListEntry
		method    string
		path      string
		shouldErr bool
		err       error
	}{
		// Access list with default deny that allows viewer only
		{
			name:   "user with viewer role claim and default deny acl going to app/viewer via get",
			claims: viewer, acl: defaultDenyACL, method: "GET", path: "/app/viewer", shouldErr: false,
		},
		{
			name:   "user with viewer role claim and default deny acl going to app/editor via get",
			claims: viewer, acl: defaultDenyACL, method: "GET", path: "/app/editor", shouldErr: false,
		},
		{
			name:   "user with viewer role claim and default deny acl going to app/admin via get",
			claims: viewer, acl: defaultDenyACL, method: "GET", path: "/app/admin", shouldErr: false,
		},
		{
			name:   "user with editor role claim and default deny acl going to app/viewer via get",
			claims: editor, acl: defaultDenyACL, method: "GET", path: "/app/viewer", shouldErr: true, err: ErrAccessNotAllowed,
		},
		{
			name:   "user with editor role claim and default deny acl going to app/editor via get",
			claims: editor, acl: defaultDenyACL, method: "GET", path: "/app/editor", shouldErr: true, err: ErrAccessNotAllowed,
		},
		{
			name:   "user with editor role claim and default deny acl going to app/admin via get",
			claims: editor, acl: defaultDenyACL, method: "GET", path: "/app/admin", shouldErr: true, err: ErrAccessNotAllowed,
		},
		// Access list with default allow that denies editor
		{
			name:   "user with viewer role claim and default allow acl going to app/viewer via get",
			claims: viewer, acl: defaultAllowACL, method: "GET", path: "/app/viewer", shouldErr: false,
		},
		{
			name:   "user with viewer role claim and default allow acl going to app/editor via get",
			claims: viewer, acl: defaultAllowACL, method: "GET", path: "/app/editor", shouldErr: false,
		},
		{
			name:   "user with viewer role claim and default allow acl going to app/admin via get",
			claims: viewer, acl: defaultAllowACL, method: "GET", path: "/app/admin", shouldErr: false,
		},
		{
			name:   "user with editor role claim and default allow acl going to app/viewer via get",
			claims: editor, acl: defaultAllowACL, method: "GET", path: "/app/viewer", shouldErr: true, err: ErrAccessNotAllowed,
		},
		{
			name:   "user with editor role claim and default allow acl going to app/editor via get",
			claims: editor, acl: defaultAllowACL, method: "GET", path: "/app/editor", shouldErr: true, err: ErrAccessNotAllowed,
		},
		{
			name:   "user with editor role claim and default allow acl going to app/admin via get",
			claims: editor, acl: defaultAllowACL, method: "GET", path: "/app/admin", shouldErr: true, err: ErrAccessNotAllowed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			validator := NewTokenValidator()
			tokenConfig := NewCommonTokenConfig()
			tokenConfig.TokenIssuer = "localhost"
			tokenConfig.TokenSecret = secret
			validator.TokenConfigs = []*CommonTokenConfig{tokenConfig}
			validator.AccessList = test.acl

			if err := validator.ConfigureTokenBackends(); err != nil {
				t.Fatalf("validator backend configuration failed: %s", err)
			}

			handler := func(w http.ResponseWriter, r *http.Request) {
				_, _, err := validator.Authorize(r, nil)

				if test.shouldErr && err == nil {
					t.Fatalf("expected error, but got success")
				}

				if !test.shouldErr && err != nil {
					t.Fatalf("expected error, but got error: %s", err)
				}

				if test.shouldErr {
					if err.Error() != test.err.Error() {
						t.Fatalf("got: %v expect: %v", err, test.err)
					}
				}
			}

			req, err := http.NewRequest(test.method, test.path, nil)
			if err != nil {
				t.Fatal(err)
			}

			token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, test.claims)
			tokenString, err := token.SignedString([]byte(secret))
			if err != nil {
				t.Fatalf("bad token signing: %v", err)
			}
			req.Header.Set("Authorization", fmt.Sprintf("access_token=%s", tokenString))
			w := httptest.NewRecorder()
			handler(w, req)

			w.Result()
		})
	}

	if testFailed > 0 {
		t.Fatalf("Failed %d tests", testFailed)
	}
}
