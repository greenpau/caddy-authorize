package jwt

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func TestAuthorize(t *testing.T) {

	entry := NewAccessListEntry()
	entry.Allow()
	if err := entry.SetClaim("roles"); err != nil {
		t.Fatalf("default access list configuration error: %s", err)
	}

	for _, v := range []string{"anonymous", "guest"} {
		if err := entry.AddValue(v); err != nil {
			t.Fatalf("default access list configuration error: %s", err)
		}
	}

	secret := "1234567890abcdef-ghijklmnopqrstuvwxyz"
	newToken := func(scope string) string {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"exp":   time.Now().Add(10 * time.Minute).Unix(),
			"iat":   time.Now().Add(10 * time.Minute * -1).Unix(),
			"nbf":   time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
			"roles": "guest",
			"org":   "somewhere",
			"scope": scope,
		})

		tokenString, err := token.SignedString([]byte(secret))
		if err != nil {
			t.Fatalf("bad token signing: %v", err)
		}

		return tokenString
	}

	var tests = []struct {
		name      string
		tokenName string
		sources   []string
		header    []string
		cookie    *http.Cookie
		parameter []string
		scope     string
		expect    bool
		err       error
	}{
		{
			name:    "header with default sources and names",
			scope:   "somewhere",
			sources: allTokenSources,
			header:  []string{"access_token", newToken("somewhere")},
			expect:  true,
		},
		{
			name:    "cookie with default sources and names",
			scope:   "somewhere",
			sources: allTokenSources,
			cookie: &http.Cookie{
				Name:  "access_token",
				Value: newToken("somewhere"),
			},
			expect: true,
		},
		{
			name:      "query with default sources and names",
			scope:     "somewhere",
			sources:   allTokenSources,
			parameter: []string{"access_token", newToken("somewhere")},
			expect:    true,
		},
		{
			name:      "query over header and default names",
			scope:     "cape",
			sources:   []string{"query", "header"},
			header:    []string{"access_token", newToken("boots")},
			parameter: []string{"access_token", newToken("cape")},
			expect:    true,
		},
		{
			name:      "query over header and both default names",
			scope:     "cape",
			sources:   []string{"query", "header"},
			header:    []string{"access_token", newToken("boots")},
			parameter: []string{"jwt_access_token", newToken("cape")},
			expect:    true,
		},
		{
			name:      "header with default sources and custom name",
			tokenName: "how_who_woh",
			scope:     "apex",
			sources:   allTokenSources,
			header:    []string{"how_who_woh", newToken("apex")},
			expect:    true,
		},
		{
			name:      "header with custom name check overwrite",
			tokenName: "how_who_woh",
			sources:   []string{tokenSourceHeader},
			header:    []string{"access_token", newToken("apex")},
			expect:    false,
			err:       ErrNoTokenFound,
		},
		{
			name:    "header with custom sources and no data where source is expected",
			sources: []string{tokenSourceCookie},
			header:  []string{"access_token", newToken("apex")},
			expect:  false,
			err:     nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			validator := NewTokenValidator()

			if test.tokenName != "" {
				validator.SetTokenName(test.tokenName)
			}
			validator.TokenSecret = secret
			validator.TokenIssuer = "localhost"
			validator.AccessList = []*AccessListEntry{entry}
			validator.TokenSources = test.sources

			if err := validator.ConfigureTokenBackends(); err != nil {
				t.Fatalf("validator backend configuration failed: %s", err)
			}

			handler := func(w http.ResponseWriter, r *http.Request) {
				u, got, err := validator.Authorize(r)

				if got != test.expect {
					t.Log(err)
					t.Fatalf("got: %t expect: %t", got, test.expect)
				}

				if !errors.Is(err, test.err) {
					t.Fatalf("got: %v expect: %v", err, test.err)
				}

				if len(test.scope) > 0 && u.Scope != test.scope {
					t.Fatalf("got: %q expect: %q", u.Scope, test.scope)
				}

			}

			req, err := http.NewRequest("GET", "/test/no/exists", nil)
			if err != nil {
				t.Fatal(err)
			}

			if test.header != nil && len(test.header) == 2 {
				req.Header.Set("Authorization", fmt.Sprintf("%s=%s", test.header[0], test.header[1]))
			}

			if test.cookie != nil {
				req.AddCookie(test.cookie)
			}

			if test.parameter != nil && len(test.parameter) == 2 {
				q := req.URL.Query()
				q.Set(test.parameter[0], test.parameter[1])
				req.URL.RawQuery = q.Encode()
			}

			w := httptest.NewRecorder()
			handler(w, req)

			w.Result()
		})
	}
}
