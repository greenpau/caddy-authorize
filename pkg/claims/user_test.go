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

package claims

import (
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"reflect"
	"testing"
	"time"

	"github.com/greenpau/caddy-auth-jwt/pkg/backends"

	jwtlib "github.com/dgrijalva/jwt-go"
)

type TestUserClaims struct {
	Roles         []string `json:"roles,omitempty" xml:"roles" yaml:"roles,omitempty"`
	Role          string   `json:"role,omitempty" xml:"role" yaml:"role,omitempty"`
	Groups        []string `json:"groups,omitempty" xml:"groups" yaml:"groups,omitempty"`
	Group         string   `json:"group,omitempty" xml:"group" yaml:"group,omitempty"`
	Organizations []string `json:"org,omitempty" xml:"org" yaml:"org,omitempty"`
	Address       string   `json:"addr,omitempty" xml:"addr" yaml:"addr,omitempty"`
	jwtlib.StandardClaims
}

func TestReadUserClaims(t *testing.T) {
	testFailed := 0
	secret := "75f03764-147c-4d87-b2f0-4fda89e331c8"
	backend, err := backends.NewSecretKeyTokenBackend(secret)
	if err != nil {
		t.Fatalf("failed creating secret key backend: %s", err)
	}

	tests := []struct {
		name      string
		claims    *TestUserClaims
		roles     []string
		addr      string
		err       error
		shouldErr bool
	}{
		{
			name: "user with roles claims and ip address",
			claims: &TestUserClaims{
				Roles: []string{"admin", "editor", "viewer"},
				StandardClaims: jwtlib.StandardClaims{
					ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
					IssuedAt:  time.Now().Add(10 * time.Minute * -1).Unix(),
					NotBefore: time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
					Subject:   "smithj@outlook.com",
				},
			},
			roles: []string{"admin", "editor", "viewer"},
			addr:  "127.0.0.1",
		},
		{
			name: "user with groups claims and ip address",
			claims: &TestUserClaims{
				Groups: []string{"admin", "editor", "viewer"},
				StandardClaims: jwtlib.StandardClaims{
					ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
					IssuedAt:  time.Now().Add(10 * time.Minute * -1).Unix(),
					NotBefore: time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
					Subject:   "smithj@outlook.com",
				},
			},
			roles: []string{"admin", "editor", "viewer"},
			addr:  "127.0.0.1",
		},
		{
			name: "user with role claim and ip address",
			claims: &TestUserClaims{
				Role:    "admin",
				Address: "192.168.1.1",
				StandardClaims: jwtlib.StandardClaims{
					ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
					IssuedAt:  time.Now().Add(10 * time.Minute * -1).Unix(),
					NotBefore: time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
					Subject:   "smithj@outlook.com",
				},
			},
			roles: []string{"admin"},
			addr:  "192.168.1.1",
		},
		{
			name: "user with group claim and ip address",
			claims: &TestUserClaims{
				Group:   "admin",
				Address: "192.168.1.1",
				StandardClaims: jwtlib.StandardClaims{
					ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
					IssuedAt:  time.Now().Add(10 * time.Minute * -1).Unix(),
					NotBefore: time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
					Subject:   "smithj@outlook.com",
				},
			},
			roles: []string{"admin"},
			addr:  "192.168.1.1",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Logf("%v", test)

			inputToken := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, test.claims)
			inputTokenString, err := inputToken.SignedString([]byte(secret))
			if err != nil {
				t.Fatalf("failed signing claims: %s", err)
			}
			t.Logf("Encoded input token: %s", inputTokenString)

			token, err := jwtlib.Parse(inputTokenString, backend.ProvideKey)
			if err != nil {
				t.Fatalf("failed parsing token: %s", err)
			}
			if !token.Valid {
				t.Fatalf("token is invalid")
			}

			testClaims, err := ParseClaims(token)
			if err != nil {
				t.Fatalf("failed parsing claims: %s", err)
			}
			t.Logf("Parsed claims: %v", testClaims)
			t.Logf("Roles: %v", testClaims.Roles)
			if !reflect.DeepEqual(testClaims.Roles, test.roles) {
				t.Fatalf("role mismatch: %s (token) vs %s (expected)", testClaims.Roles, test.roles)
			}
		})
	}

	if testFailed > 0 {
		t.Fatalf("Failed %d tests", testFailed)
	}
}

func TestUserHSClaims(t *testing.T) {
	claims := &UserClaims{}
	claims.ExpiresAt = time.Now().Add(time.Duration(900) * time.Second).Unix()
	claims.Name = "Greenberg, Paul"
	claims.Email = "greenpau@outlook.com"
	claims.Origin = "localhost"
	claims.Subject = "greenpau@outlook.com"
	claims.Roles = append(claims.Roles, "anonymous")
	secret := "75f03764-147c-4d87-b2f0-4fda89e331c8"
	token, err := claims.GetToken("HS512", []byte(secret))
	if err != nil {
		t.Fatalf("Failed to get JWT token for %v: %s", claims, err)
	}
	t.Logf("Token: %s", token)
}

func TestAppMetadataAuthorizationRoles(t *testing.T) {
	secret := "75f03764147c4d87b2f04fda89e331c808ab50a932914e758ae17c7847ef27fa"
	encodedToken := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9." +
		"eyJleHAiOjI1NDI3MTkzOTgsInN1YiI6ImdyZWVucGF1QG91dGxvb2suY29tIiwibmFtZSI6IkdyZWV" +
		"uYmVyZywgUGF1bCIsImVtYWlsIjoiZ3JlZW5wYXVAb3V0bG9vay5jb20iLCJhcHBfbWV0YWRhdGEiOn" +
		"siYXV0aG9yaXphdGlvbiI6eyJyb2xlcyI6WyJhZG1pbiIsImVkaXRvciIsImd1ZXN0Il19fSwib3JpZ" +
		"2luIjoibG9jYWxob3N0In0." +
		"KnHyq1WhL3VbhVaHZBc5JyvHMZbU72505H5y9QJmLADmTfDSJbQ-Odjsnl5zZldG_PBMQ6XkvE11hsmXOIqyKA"
	expectedRoles := []string{"admin", "editor", "guest"}

	t.Logf("token Secret: %s", secret)
	t.Logf("encoded Token: %s", encodedToken)

	token, err := jwtlib.Parse(encodedToken, func(token *jwtlib.Token) (interface{}, error) {
		if _, validMethod := token.Method.(*jwtlib.SigningMethodHMAC); !validMethod {
			return nil, errors.ErrUnexpectedSigningMethod.WithArgs(token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		t.Fatalf("failed parsing the encoded token: %s", err)
	}

	t.Logf("token: %v", token)

	claimMap := token.Claims.(jwtlib.MapClaims)
	claims, err := NewUserClaimsFromMap(claimMap)
	if err != nil {
		t.Fatalf("failed parsing claims for token: %s", err)
	}

	t.Logf("claims: %v", claims)

	if len(claims.Roles) == 0 {
		t.Fatalf("no roles found, expecting %s", expectedRoles)
	}

	if len(claims.Roles) != len(expectedRoles) {
		t.Fatalf("role count mismatch: %d (token) vs %d (expected)", len(claims.Roles), len(expectedRoles))
	}

	if !reflect.DeepEqual(claims.Roles, expectedRoles) {
		t.Fatalf("role mismatch: %s (token) vs %s (expected)", claims.Roles, expectedRoles)
	}

	t.Logf("token roles: %s", claims.Roles)

	return
}

func TestRealmAccessRoles(t *testing.T) {
	secret := "75f03764147c4d87b2f04fda89e331c808ab50a932914e758ae17c7847ef27fa"
	encodedToken := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjI1NDI3MTkzOTgsInN1YiI6ImdyZWVucGF1QG91dGxvb2suY29tIiwibmFtZSI6IkdyZWVuYmVyZywgUGF1bCIsImVtYWlsIjoiZ3JlZW5wYXVAb3V0bG9vay5jb20iLCJhcHBfbWV0YWRhdGEiOnsiYXV0aG9yaXphdGlvbiI6eyJyb2xlcyI6WyJhZG1pbiIsImVkaXRvciIsImd1ZXN0Il19fSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm1hcmtldGluZyIsImZpbmFuY2UiLCJ0cmFpbmluZyJdfSwib3JpZ2luIjoibG9jYWxob3N0In0.IiYC_7JCpZiKN7dvwXCLw94HvL8sMBqKACp6zthIXg8GyU-PXSleGnjc9wduBFqWfMtl5oP_JrJzCbsWiInghA"
	expectedRoles := []string{"admin", "editor", "guest", "marketing", "finance", "training"}

	t.Logf("token Secret: %s", secret)
	t.Logf("encoded Token: %s", encodedToken)

	token, err := jwtlib.Parse(encodedToken, func(token *jwtlib.Token) (interface{}, error) {
		if _, validMethod := token.Method.(*jwtlib.SigningMethodHMAC); !validMethod {
			return nil, errors.ErrUnexpectedSigningMethod.WithArgs(token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		t.Fatalf("failed parsing the encoded token: %s", err)
	}

	t.Logf("token: %v", token)

	claimMap := token.Claims.(jwtlib.MapClaims)
	claims, err := NewUserClaimsFromMap(claimMap)
	if err != nil {
		t.Fatalf("failed parsing claims for token: %s", err)
	}

	t.Logf("claims: %v", claims)

	if len(claims.Roles) == 0 {
		t.Fatalf("no roles found, expecting %s", expectedRoles)
	}

	if len(claims.Roles) != len(expectedRoles) {
		t.Fatalf("role count mismatch: %d (token) vs %d (expected)", len(claims.Roles), len(expectedRoles))
	}

	if !reflect.DeepEqual(claims.Roles, expectedRoles) {
		t.Fatalf("role mismatch: %s (token) vs %s (expected)", claims.Roles, expectedRoles)
	}

	t.Logf("token roles: %s", claims.Roles)

	return
}

func TestAnonymousGuestRoles(t *testing.T) {
	secret := "75f03764147c4d87b2f04fda89e331c808ab50a932914e758ae17c7847ef27fa"
	encodedToken := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9." +
		"eyJleHAiOjI1NDI3MTkzOTgsInN1YiI6ImdyZWVucGF1QG91dGxvb2suY29tIiwibmFtZSI6IkdyZW" +
		"VuYmVyZywgUGF1bCIsImVtYWlsIjoiZ3JlZW5wYXVAb3V0bG9vay5jb20iLCJvcmlnaW4iOiJsb2Nh" +
		"bGhvc3QifQ." +
		"INRBEsx7b4sewCmNCQxRSN3Hk_sT5BMbjlq_iPdbvkYiWnORS93xYSAei78GWEMDepc6ECTSGhqVL-sDFCbPoA"
	expectedRoles := []string{"anonymous", "guest"}

	t.Logf("token Secret: %s", secret)
	t.Logf("encoded Token: %s", encodedToken)

	token, err := jwtlib.Parse(encodedToken, func(token *jwtlib.Token) (interface{}, error) {
		if _, validMethod := token.Method.(*jwtlib.SigningMethodHMAC); !validMethod {
			return nil, errors.ErrUnexpectedSigningMethod.WithArgs(token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		t.Fatalf("failed parsing the encoded token: %s", err)
	}

	t.Logf("token: %v", token)

	claimMap := token.Claims.(jwtlib.MapClaims)
	claims, err := NewUserClaimsFromMap(claimMap)
	if err != nil {
		t.Fatalf("failed parsing claims for token: %s", err)
	}

	t.Logf("claims: %v", claims)

	if len(claims.Roles) == 0 {
		t.Fatalf("no roles found, expecting %s", expectedRoles)
	}

	if len(claims.Roles) != len(expectedRoles) {
		t.Fatalf("role count mismatch: %d (token) vs %d (expected)", len(claims.Roles), len(expectedRoles))
	}

	if !reflect.DeepEqual(claims.Roles, expectedRoles) {
		t.Fatalf("role mismatch: %s (token) vs %s (expected)", claims.Roles, expectedRoles)
	}

	t.Logf("token roles: %s", claims.Roles)

	return
}

func TestUserRSClaims(t *testing.T) {
	claims := &UserClaims{}
	claims.ExpiresAt = time.Now().Add(time.Duration(900) * time.Second).Unix()
	claims.Name = "Jones, Nika"
	claims.Email = "njones@outlook.example.com"
	claims.Origin = "localhost"
	claims.Subject = "njones@outlook.example.com"
	claims.Roles = append(claims.Roles, "anonymous")

	priKey, err := jwtlib.ParseRSAPrivateKeyFromPEM([]byte(userTestRSPriKey))
	if err != nil {
		t.Fatal(err)
	}
	token, err := claims.GetToken("RS512", priKey)
	if err != nil {
		t.Fatalf("Failed to get JWT token for %v: %s", claims, err)
	}
	t.Logf("Token: %s", token)
}

// testPriKey2 is the same as "test-priv-2.pem"
var userTestRSPriKey = `-----BEGIN RSA PRIVATE KEY-----
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
