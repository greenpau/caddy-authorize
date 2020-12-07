// Copyright 2020 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package validator

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwtlib "github.com/dgrijalva/jwt-go"
	jwtacl "github.com/greenpau/caddy-auth-jwt/pkg/acl"
	jwtconfig "github.com/greenpau/caddy-auth-jwt/pkg/config"
	jwterrors "github.com/greenpau/caddy-auth-jwt/pkg/errors"
)

func TestRSAValidation(t *testing.T) {

	entry := jwtacl.NewAccessListEntry()
	entry.Allow()
	if err := entry.SetClaim("roles"); err != nil {
		t.Fatalf("default access list configuration error: %s", err)
	}

	for _, v := range []string{"anonymous", "guest"} {
		if err := entry.AddValue(v); err != nil {
			t.Fatalf("default access list configuration error: %s", err)
		}
	}

	priKey2, err := jwtlib.ParseRSAPrivateKeyFromPEM([]byte(validatorTestRSPrivKey2))
	if err != nil {
		t.Fatal(err)
	}

	priKey, err := jwtlib.ParseRSAPrivateKeyFromPEM([]byte(validatorTestRSPrivKey))
	if err != nil {
		t.Fatal(err)
	}

	newToken := func(t *testing.T, kid *string, key interface{}) string {
		token := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, jwtlib.MapClaims{
			"exp":   time.Now().Add(10 * time.Minute).Unix(),
			"iat":   time.Now().Add(10 * time.Minute * -1).Unix(),
			"nbf":   time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
			"roles": "guest",
			"org":   "somewhere",
			"scope": "dance",
		})

		if kid != nil {
			token.Header["kid"] = *kid
		}
		tokenString, err := token.SignedString(key)
		if err != nil {
			t.Fatalf("bad token signing: %v", err)
		}

		return tokenString
	}

	tokenKeys := make(map[string]interface{})
	tokenKeys["0"] = &priKey.PublicKey
	tokenKeys["pub"] = &priKey.PublicKey
	tokenKeys["pri"] = priKey

	nilKid := "零" // so we can represent nil as a string

	type expect struct {
		ok  bool
		err error
	}
	tests := []struct {
		name string
		kid  string
		key  interface{}
		expect
	}{
		{
			name:   "nil kid",
			kid:    nilKid,
			key:    priKey,
			expect: expect{ok: true, err: nil},
		},
		{
			name:   "named kid (pub)",
			kid:    "pub",
			key:    priKey,
			expect: expect{ok: true, err: nil},
		},
		{
			name:   "named kid (private key)",
			kid:    "pri",
			key:    priKey,
			expect: expect{ok: true, err: nil},
		},
		{
			name:   "unkown kid",
			kid:    "who_are_you",
			key:    priKey,
			expect: expect{ok: false, err: jwterrors.ErrInvalid.WithArgs([]string{jwterrors.ErrUnexpectedKID.Error()})},
		},
		{
			name:   "nil kid but bad key",
			kid:    nilKid,
			key:    priKey2,
			expect: expect{ok: false, err: jwterrors.ErrInvalid.WithArgs([]string{"crypto/rsa: verification error"})},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			validator := NewTokenValidator()
			tokenConfig := jwtconfig.NewCommonTokenConfig()
			for k, v := range tokenKeys {
				tokenConfig.AddTokenKey(k, v)
			}
			validator.TokenConfigs = []*jwtconfig.CommonTokenConfig{tokenConfig}
			validator.SetTokenName("blue")
			validator.AccessList = []*jwtacl.AccessListEntry{entry}
			validator.TokenSources = AllTokenSources

			if err := validator.ConfigureTokenBackends(); err != nil {
				t.Fatalf("validator backend configuration failed: %s", err)
			}

			var KID *string
			if test.kid != nilKid {
				KID = &test.kid
			}

			_, ok, err := validator.ValidateToken(newToken(t, KID, test.key), nil)
			if test.expect.ok != ok {
				t.Errorf("got: %t expected: %t", ok, test.expect.ok)
			}
			if err != nil && test.expect.err != nil {
				if err.Error() != test.expect.err.Error() {
					t.Errorf("got: %v expected: %v", err, test.expect.err)
				}
			} else if test.expect.err != nil && err == nil {
				t.Errorf("got: %v expected: %v", err, test.expect.err)
			}
		})
	}
}

func TestAuthorizationSources(t *testing.T) {

	entry := jwtacl.NewAccessListEntry()
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
		token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, jwtlib.MapClaims{
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
			sources: AllTokenSources,
			header:  []string{"access_token", newToken("somewhere")},
			expect:  true,
		},
		{
			name:    "cookie with default sources and names",
			scope:   "somewhere",
			sources: AllTokenSources,
			cookie: &http.Cookie{
				Name:  "access_token",
				Value: newToken("somewhere"),
			},
			expect: true,
		},
		{
			name:      "query with default sources and names",
			scope:     "somewhere",
			sources:   AllTokenSources,
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
			sources:   AllTokenSources,
			header:    []string{"how_who_woh", newToken("apex")},
			expect:    true,
		},
		{
			name:      "header with custom name check overwrite",
			tokenName: "how_who_woh",
			sources:   []string{tokenSourceHeader},
			header:    []string{"access_token", newToken("apex")},
			expect:    false,
			err:       jwterrors.ErrNoTokenFound,
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
				validator.OverwriteTokenName(test.tokenName)
			}

			tokenConfig := jwtconfig.NewCommonTokenConfig()
			tokenConfig.TokenSecret = secret
			validator.TokenConfigs = []*jwtconfig.CommonTokenConfig{tokenConfig}
			validator.AccessList = []*jwtacl.AccessListEntry{entry}
			validator.TokenSources = test.sources

			if err := validator.ConfigureTokenBackends(); err != nil {
				t.Fatalf("validator backend configuration failed: %s", err)
			}

			handler := func(w http.ResponseWriter, r *http.Request) {
				u, got, err := validator.Authorize(r, nil)

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

func TestAuthorize(t *testing.T) {
	testFailed := 0
	secret := "1234567890abcdef-ghijklmnopqrstuvwxyz"
	entry := jwtacl.NewAccessListEntry()
	entry.Allow()
	if err := entry.SetClaim("roles"); err != nil {
		t.Fatalf("default access list configuration error: %s", err)
	}

	for _, v := range []string{"anonymous", "guest"} {
		if err := entry.AddValue(v); err != nil {
			t.Fatalf("default access list configuration error: %s", err)
		}
	}

	tests := []struct {
		name      string
		claims    jwtlib.MapClaims
		opts      *jwtconfig.TokenValidatorOptions
		err       error
		shouldErr bool
	}{
		{
			name: "user with anonymous claims",
			claims: jwtlib.MapClaims{
				"exp":    time.Now().Add(10 * time.Minute).Unix(),
				"iat":    time.Now().Add(10 * time.Minute * -1).Unix(),
				"nbf":    time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
				"name":   "Smith, John",
				"email":  "smithj@outlook.com",
				"origin": "localhost",
				"sub":    "smithj@outlook.com",
				"roles":  []string{"guest", "anonymous"},
			},
			opts:      jwtconfig.NewTokenValidatorOptions(),
			shouldErr: false,
		},
		{
			name: "user with anonymous claims and mismatched ip address",
			claims: jwtlib.MapClaims{
				"exp":    time.Now().Add(10 * time.Minute).Unix(),
				"iat":    time.Now().Add(10 * time.Minute * -1).Unix(),
				"nbf":    time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
				"name":   "Smith, John",
				"email":  "smithj@outlook.com",
				"origin": "localhost",
				"sub":    "smithj@outlook.com",
				"roles":  []string{"guest", "anonymous"},
				"addr":   "192.168.1.1",
			},
			opts: &jwtconfig.TokenValidatorOptions{
				ValidateSourceAddress: true,
				Metadata: map[string]interface{}{
					"address": "192.168.100.100",
				},
			},
			shouldErr: true,
			err:       jwterrors.ErrSourceAddressMismatch.WithArgs("192.168.1.1", "192.168.100.100"),
		},
		{
			name: "user with anonymous claims and original ip address",
			claims: jwtlib.MapClaims{
				"exp":    time.Now().Add(10 * time.Minute).Unix(),
				"iat":    time.Now().Add(10 * time.Minute * -1).Unix(),
				"nbf":    time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
				"name":   "Smith, John",
				"email":  "smithj@outlook.com",
				"origin": "localhost",
				"sub":    "smithj@outlook.com",
				"roles":  []string{"guest", "anonymous"},
				"addr":   "192.168.1.1",
			},
			opts: &jwtconfig.TokenValidatorOptions{
				ValidateSourceAddress: true,
				Metadata: map[string]interface{}{
					"address": "192.168.1.1",
				},
			},
			shouldErr: false,
		},
		{
			name: "user with anonymous claims, original ip address, and bearer token",
			claims: jwtlib.MapClaims{
				"exp":    time.Now().Add(10 * time.Minute).Unix(),
				"iat":    time.Now().Add(10 * time.Minute * -1).Unix(),
				"nbf":    time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
				"name":   "Smith, John",
				"email":  "smithj@outlook.com",
				"origin": "localhost",
				"sub":    "smithj@outlook.com",
				"roles":  []string{"guest", "anonymous"},
				"addr":   "192.168.1.1",
			},
			opts: &jwtconfig.TokenValidatorOptions{
				ValidateSourceAddress: true,
				Metadata: map[string]interface{}{
					"address": "192.168.1.1",
				},
				ValidateBearerHeader: true,
			},
			shouldErr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			validator := NewTokenValidator()
			tokenConfig := jwtconfig.NewCommonTokenConfig()
			tokenConfig.TokenSecret = secret
			validator.TokenConfigs = []*jwtconfig.CommonTokenConfig{tokenConfig}
			validator.AccessList = []*jwtacl.AccessListEntry{entry}

			if err := validator.ConfigureTokenBackends(); err != nil {
				t.Fatalf("validator backend configuration failed: %s", err)
			}

			handler := func(w http.ResponseWriter, r *http.Request) {
				_, _, err := validator.Authorize(r, test.opts)

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

			req, err := http.NewRequest("GET", "/test/no/exists", nil)
			if err != nil {
				t.Fatal(err)
			}

			token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, test.claims)
			tokenString, err := token.SignedString([]byte(secret))
			if err != nil {
				t.Fatalf("bad token signing: %v", err)
			}

			if test.opts.ValidateBearerHeader {
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenString))
			} else {
				req.Header.Set("Authorization", fmt.Sprintf("access_token=%s", tokenString))
			}
			w := httptest.NewRecorder()
			handler(w, req)

			w.Result()
		})
	}

	if testFailed > 0 {
		t.Fatalf("Failed %d tests", testFailed)
	}
}

var validatorTestRSPrivKey = `-----BEGIN RSA PRIVATE KEY-----
MIICWgIBAAKBgEMFBKcGW7iRRlJdIuF0/5YmB3ACsCd6hWCFk4FGAj7G+sd4m9GG
U/9ae9x00yvkY2Pit03B5kxHQfVAqKG6PnTzRg5cbwjPjnhFiPeLfGWMKIIEkhTa
cuIu8Tr+hmMchxCUYl9twakFl3bOVsHqmMcByJ44FII66Kl4z6k4ERKZAgMBAAEC
gYAfGugi4SeWzQ43UfTLcTLirDnNeeHqIMpglv50BFssacug4tBm+ZJotMVB95K/
D1w10tbCpxjNFFF/k4fwr/EmeuAK3aQgmsbxAgtH6hyKtYp6yrK7jabkXXJLFTaC
8aWgq7RRCazDxlJlOtn50vMUH1LHf1Z0YUC76OyzsiKC9QJBAINN8Nl11M4/3s1n
x4H0sMiyyW8DhqMrpla0IgAwuWRHmWZ1VuiWUXmv/oW+YLoFxDofukhLFT2NblFr
h5d4kW8CQQCCqnoG2Wd0fRFk1kHcGEZzJB0D1PKepOHe//ca4uNPupo45qOXaMCU
7vj7+JkZo/pEgjXaG1G00saF5KTMJgh3AkA+F82eCKrqHiou2LTwL9aqEmJPrUsu
PqYaunSZwnDpizJv0W2X7/33ndKvTKhRUAjLs9VT+q3AvfE9b6xfZRThAkBVifKe
fz45xRJY9+ZfhkjAYbjY5FP8RSZUjS6gHD4A2MDTVTFtEjdYiGTY1vKrFWzl4nQM
l2vSu1UZHAhCWPebAkAT9KpSzWqcLt7GFOHjoVpHIeuyCCkWJwS9JeP6J/QbaJq/
SMNiwTaDC1kT8uCWqTgd5u5AKOV+oyzwmj0nJu8n
-----END RSA PRIVATE KEY-----`

var validatorTestRSPrivKey2 = `-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCrf9Dn14TCRFWt/7ddDiaQeH82vB4e+L/AOZs2bTWos8b9Houp
RzO1r6QXfpP27QQ5AAGqCe/p0nxwu6W8nMzBZfVDGgGeaBz/jii4njiZgO5OBHBC
ezkgppvowJOTWb1Wut/C0svkqXRVldIkJgJHpKCf3qeQvaYnPDWS7iOVaQIDAQAB
AoGAXDORerORumfGsI9EY5ESBqXhrumgQAJ4BL5zxeUc7iAJIVhkuZOAJ3PQgpkY
r65pkMOCIYrKIyl4oZsg1bBvG71ZBbyUJGhXvx7bXLrgi7XU1ZEAjTAEN0HfALHN
x9/E5iBj4SMEeL88FDVLtLkuVPsQZcq44UUS7STGwPv0jgECQQD+CK4FVK4iiVdj
Gw+y5Hm6UTKn8y5Vpn3MdEcMhK4Y7nob0L2ykGTA37H00c67zey5qS0emv+vfrXw
VnFucNWJAkEArNOcB5kgBLyJpdcgXaNUo23enwM3gxnxhk5/xEHcCyNN/HABkt+l
9DMjLPurPtmA6EhlhLoZ00ku1PJ9Cqao4QJAKXavOM2GkrqKGfIL0O479C5Wr1Uh
Bffj5qBADIoHhKhAJBQhMmkhGN4qRMSOEtdcwT0c0TcJbtKmzbC+WQFvyQJAMyzd
0Ooorv5dC/xtmwyYLWSFPTSopWtzNz/bWXPfAnVLzGomLSWIcI0L53AGPzAMmbuG
RA0PRJ8w/OFo4VSEQQJARDK5ZogXT6/SbLmDoIDc7APhSpjLmP7QS//QXoXASzcj
xQVliDEowvVx4y+/p5Mh9kVOmU6AVq7ttep4PpFuWA==
-----END RSA PRIVATE KEY-----`

func TestAuthorizeWithPathAccessList(t *testing.T) {
	testFailed := 0
	secret := "1234567890abcdef-ghijklmnopqrstuvwxyz"

	// Viewer has access only to media, images, push, and applications
	viewer := jwtlib.MapClaims{
		"exp":    time.Now().Add(10 * time.Minute).Unix(),
		"iat":    time.Now().Add(10 * time.Minute * -1).Unix(),
		"nbf":    time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
		"name":   "Smith, John",
		"email":  "smithj@outlook.com",
		"origin": "localhost",
		"sub":    "smithj@outlook.com",
		"roles":  []string{"viewer"},
		"acl": map[string]interface{}{
			"paths": []string{
				"/*/image/**",
				"/*/media/**",
				"/*/applications/**",
				"/*/push/**",
			},
		},
	}

	// Editor has no access to users, conversations
	editor := jwtlib.MapClaims{
		"exp":    time.Now().Add(10 * time.Minute).Unix(),
		"iat":    time.Now().Add(10 * time.Minute * -1).Unix(),
		"nbf":    time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
		"name":   "Smith, Jane",
		"email":  "jane.smith@outlook.com",
		"origin": "localhost",
		"sub":    "jane.smith@outlook.com",
		"roles":  []string{"editor"},
		"acl": map[string]interface{}{
			"paths": []string{
				"/*/sessions/**",
				"/*/devices/**",
				"/*/image/**",
				"/*/media/**",
				"/*/applications/**",
				"/*/push/**",
				"/*/knocking/**",
			},
		},
	}

	admin := jwtlib.MapClaims{
		"exp":    time.Now().Add(10 * time.Minute).Unix(),
		"iat":    time.Now().Add(10 * time.Minute * -1).Unix(),
		"nbf":    time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
		"name":   "Smith, James",
		"email":  "james.smith@outlook.com",
		"origin": "localhost",
		"sub":    "james.smith@outlook.com",
		"roles":  []string{"admin"},
		"acl": map[string]interface{}{
			"paths": []string{
				"/*/users/**",
				"/*/conversations/**",
				"/*/sessions/**",
				"/*/devices/**",
				"/*/image/**",
				"/*/media/**",
				"/*/applications/**",
				"/*/push/**",
				"/*/knocking/**",
			},
		},
	}

	tests := []struct {
		name      string
		claims    jwtlib.MapClaims
		method    string
		path      string
		shouldErr bool
		err       error
	}{
		{
			name:   "user with viewer role allowed access to /app/media/avatar.png",
			claims: viewer, method: "GET", path: "/app/media/avatar.png", shouldErr: false,
		},
		{
			name:   "user with editor role allowed access to /app/media/avatar.png",
			claims: editor, method: "GET", path: "/app/media/avatar.png", shouldErr: false,
		},
		{
			name:   "user with admin role allowed access to /app/media/avatar.png",
			claims: admin, method: "GET", path: "/app/media/avatar.png", shouldErr: false,
		},
		{
			name:   "user with viewer role denied access to /app/sessions/generic",
			claims: viewer, method: "GET", path: "/app/sessions/generic", shouldErr: true, err: jwterrors.ErrAccessNotAllowedByPathACL,
		},
		{
			name:   "user with editor role allowed access to /app/sessions/generic",
			claims: editor, method: "GET", path: "/app/sessions/generic", shouldErr: false,
		},
		{
			name:   "user with admin role allowed access to /app/sessions/generic",
			claims: admin, method: "GET", path: "/app/sessions/generic", shouldErr: false,
		},

		{
			name:   "user with viewer role denied access to /app/users/jsmith",
			claims: viewer, method: "GET", path: "/app/users/jsmith", shouldErr: true, err: jwterrors.ErrAccessNotAllowedByPathACL,
		},
		{
			name:   "user with editor role denied access to /app/users/jsmith",
			claims: editor, method: "GET", path: "/app/users/jsmith", shouldErr: true, err: jwterrors.ErrAccessNotAllowedByPathACL,
		},
		{
			name:   "user with admin role allowed access to /app/users/jsmith",
			claims: admin, method: "GET", path: "/app/users/jsmith", shouldErr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			validator := NewTokenValidator()
			tokenConfig := jwtconfig.NewCommonTokenConfig()
			tokenConfig.TokenSecret = secret
			validator.TokenConfigs = []*jwtconfig.CommonTokenConfig{tokenConfig}
			testACL := []*jwtacl.AccessListEntry{
				&jwtacl.AccessListEntry{
					Action: "allow",
					Claim:  "roles",
					Values: []string{"admin", "editor", "viewer"},
				},
			}
			validator.AccessList = testACL

			if err := validator.ConfigureTokenBackends(); err != nil {
				t.Fatalf("validator backend configuration failed: %s", err)
			}

			handler := func(w http.ResponseWriter, r *http.Request) {
				opts := jwtconfig.NewTokenValidatorOptions()
				opts.ValidateMethodPath = true
				opts.ValidateAccessListPathClaim = true
				opts.Metadata = make(map[string]interface{})
				opts.Metadata["method"] = r.Method
				opts.Metadata["path"] = r.URL.Path
				t.Logf("claims: %s", test.claims)
				t.Logf("path: %s", r.URL.Path)
				t.Logf("method: %s", r.Method)
				_, _, err := validator.Authorize(r, opts)

				if test.shouldErr && err == nil {
					t.Logf("FAIL: expected error, but got success")
					t.Fatalf("expected error, but got success")
				}

				if !test.shouldErr && err != nil {
					t.Logf("FAIL: expected error, but got error: %s", err)
					t.Fatalf("expected error, but got error: %s", err)
				}

				if test.shouldErr {
					if err.Error() != test.err.Error() {
						t.Logf("FAIL: got: %v expect: %v", err, test.err)
						t.Fatalf("got: %v expect: %v", err, test.err)
					}
				}

				t.Logf("PASS")
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

func TestAuthorizeWithAccessList(t *testing.T) {
	testFailed := 0
	secret := "1234567890abcdef-ghijklmnopqrstuvwxyz"

	// Create access list with default deny that allows viewer only
	defaultDenyACL := []*jwtacl.AccessListEntry{
		&jwtacl.AccessListEntry{
			Action: "allow",
			Claim:  "roles",
			Values: []string{"viewer"},
		},
	}

	// Create access list with default allow that denies editor
	defaultAllowACL := []*jwtacl.AccessListEntry{
		&jwtacl.AccessListEntry{
			Action: "deny",
			Claim:  "roles",
			Values: []string{"editor"},
		},
		&jwtacl.AccessListEntry{
			Action: "allow",
			Claim:  "roles",
			Values: []string{"any"},
		},
	}

	// Create access list with default deny and HTTP Method and Path rules
	customACL := []*jwtacl.AccessListEntry{
		&jwtacl.AccessListEntry{
			Action:  "deny",
			Claim:   "roles",
			Values:  []string{"editor"},
			Methods: []string{"GET"},
			Path:    "/app/page1/blocked",
		},
		&jwtacl.AccessListEntry{
			Action:  "deny",
			Claim:   "roles",
			Values:  []string{"editor"},
			Methods: []string{"GET"},
			Path:    "/app/page2/blocked",
		},
		&jwtacl.AccessListEntry{
			Action:  "allow",
			Claim:   "roles",
			Values:  []string{"editor"},
			Methods: []string{"GET"},
			Path:    "/app/page3/allowed",
		},
		&jwtacl.AccessListEntry{
			Action: "allow",
			Claim:  "roles",
			Values: []string{"viewer"},
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
		acl       []*jwtacl.AccessListEntry
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
			claims: editor, acl: defaultDenyACL, method: "GET", path: "/app/viewer", shouldErr: true, err: jwterrors.ErrAccessNotAllowed,
		},
		{
			name:   "user with editor role claim and default deny acl going to app/editor via get",
			claims: editor, acl: defaultDenyACL, method: "GET", path: "/app/editor", shouldErr: true, err: jwterrors.ErrAccessNotAllowed,
		},
		{
			name:   "user with editor role claim and default deny acl going to app/admin via get",
			claims: editor, acl: defaultDenyACL, method: "GET", path: "/app/admin", shouldErr: true, err: jwterrors.ErrAccessNotAllowed,
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
			claims: editor, acl: defaultAllowACL, method: "GET", path: "/app/viewer", shouldErr: true, err: jwterrors.ErrAccessNotAllowed,
		},
		{
			name:   "user with editor role claim and default allow acl going to app/editor via get",
			claims: editor, acl: defaultAllowACL, method: "GET", path: "/app/editor", shouldErr: true, err: jwterrors.ErrAccessNotAllowed,
		},
		{
			name:   "user with editor role claim and default allow acl going to app/admin via get",
			claims: editor, acl: defaultAllowACL, method: "GET", path: "/app/admin", shouldErr: true, err: jwterrors.ErrAccessNotAllowed,
		},
		// Custom ACL
		{
			name:   "user with editor role claim and custom acl going to /app/page1/blocked via get",
			claims: editor, acl: customACL, method: "GET", path: "/app/page1/blocked", shouldErr: true, err: jwterrors.ErrAccessNotAllowed,
		},
		{
			name:   "user with editor role claim and custom acl going to /app/page2/blocked via get",
			claims: editor, acl: customACL, method: "GET", path: "/app/page2/blocked", shouldErr: true, err: jwterrors.ErrAccessNotAllowed,
		},
		{
			name:   "user with editor role claim and custom acl going to /app/page3/allowed via get",
			claims: editor, acl: customACL, method: "GET", path: "/app/page3/allowed", shouldErr: false,
		},
		{
			name:   "user with viewer role claim and custom acl going to /app/page1/blocked via get",
			claims: viewer, acl: customACL, method: "GET", path: "/app/page1/blocked", shouldErr: false,
		},
		{
			name:   "user with viewer role claim and custom acl going to /app/page2/blocked via get",
			claims: viewer, acl: customACL, method: "GET", path: "/app/page2/blocked", shouldErr: false,
		},
		{
			name:   "user with viewer role claim and custom acl going to /app/page3/allowed via get",
			claims: viewer, acl: customACL, method: "GET", path: "/app/page3/allowed", shouldErr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			validator := NewTokenValidator()
			tokenConfig := jwtconfig.NewCommonTokenConfig()
			tokenConfig.TokenSecret = secret
			validator.TokenConfigs = []*jwtconfig.CommonTokenConfig{tokenConfig}
			validator.AccessList = test.acl

			if err := validator.ConfigureTokenBackends(); err != nil {
				t.Fatalf("validator backend configuration failed: %s", err)
			}

			handler := func(w http.ResponseWriter, r *http.Request) {
				opts := jwtconfig.NewTokenValidatorOptions()
				for _, entry := range test.acl {
					if len(entry.Methods) > 0 || entry.Path != "" {
						opts.ValidateMethodPath = true
						break
					}
				}
				if opts.ValidateMethodPath {
					opts.Metadata = make(map[string]interface{})
					opts.Metadata["method"] = r.Method
					opts.Metadata["path"] = r.URL.Path
				}
				t.Logf("role: %s", test.claims["roles"].([]string)[0])
				t.Logf("path: %s", r.URL.Path)
				t.Logf("method: %s", r.Method)
				_, _, err := validator.Authorize(r, opts)

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
