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

package acl

import (
	"fmt"
	jwtclaims "github.com/greenpau/caddy-auth-jwt/pkg/claims"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"testing"
	"time"
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
			err:        errors.ErrEmptyClaim,
		},
		{
			name:       "unsupported org claim",
			action:     "allow",
			claim:      "org",
			values:     []string{"contoso"},
			shouldFail: false,
			shouldErr:  true,
			err:        errors.ErrUnsupportedClaim.WithArgs("org"),
		},
		{
			name:       "invalid action",
			action:     "foo",
			claim:      "roles",
			values:     []string{"anonymous"},
			shouldFail: false,
			shouldErr:  true,
			err:        errors.ErrUnsupportedACLAction.WithArgs("foo"),
		},
		{
			name:       "empty action",
			action:     "",
			claim:      "roles",
			values:     []string{"anonymous"},
			shouldFail: false,
			shouldErr:  true,
			err:        errors.ErrEmptyACLAction,
		},
		{
			name:       "empty claim value",
			action:     "allow",
			claim:      "roles",
			values:     []string{},
			shouldFail: false,
			shouldErr:  true,
			err:        errors.ErrEmptyValue,
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
		claims *jwtclaims.UserClaims
	}{
		{
			allow: false,
			claims: &jwtclaims.UserClaims{
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
			claims: &jwtclaims.UserClaims{
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
			claims: &jwtclaims.UserClaims{
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
			claims: &jwtclaims.UserClaims{
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
			claims: &jwtclaims.UserClaims{
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
		if err != errors.ErrEmptyACLAction {
			t.Fatalf("error mismatch: %s (received) vs %s (expected)", err, errors.ErrEmptyACLAction)
		}
	} else {
		t.Fatalf("expected error validating empty action")
	}
	entry1.Action = "foo bar"
	if err := entry1.Validate(); err != nil {
		if err.Error() != errors.ErrUnsupportedACLAction.WithArgs("foo bar").Error() {
			t.Fatalf("error mismatch: %s (received) vs %s (expected)", err, errors.ErrUnsupportedACLAction.WithArgs("foo bar"))
		}
	} else {
		t.Fatalf("expected error validating invalid action")
	}
	entry1.Allow()

	if err := entry1.Validate(); err != nil {
		if err.Error() != errors.ErrEmptyACLClaim.Error() {
			t.Fatalf("error mismatch: %s (received) vs %s (expected)", err, errors.ErrEmptyACLClaim)
		}
	} else {
		t.Fatalf("expected error validating invalid claim")
	}

	if err := entry1.SetClaim("roles"); err != nil {
		t.Fatalf("failed to set claim roles: %s", err)
	}

	if err := entry1.Validate(); err != nil {
		if err.Error() != errors.ErrNoValues.Error() {
			t.Fatalf("error mismatch: %s (received) vs %s (expected)", err, errors.ErrNoValues)
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
			claimAllowed, abortProcessing := entry.IsClaimAllowed(persona.claims, nil)
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

func TestMatchPathBasedACL(t *testing.T) {
	testFailed := 0
	tests := []struct {
		pattern         string
		matchedPaths    []string
		mismatchedPaths []string
	}{
		{
			pattern: "/*/media/**",
			matchedPaths: []string{
				"/app/media/icon.png",
				"/app/media/icon~png",
				"/app/media/assets/icon.png",
				"/app/media/assets/images/icon.png",
			},
			mismatchedPaths: []string{
				"/app/assets/media/icon.png",
				"/app/assets/media/assets/icon.png",
				"/app/assets/media/assets/images/icon.png",
				"/media/icon.png",
			},
		},
		{
			pattern: "/*/media/*",
			matchedPaths: []string{
				"/app/media/icon.png",
				"/app/media/icon~png",
			},
			mismatchedPaths: []string{
				"/app/media/assets/images/icon.png",
				"/app/media/assets/icon.png",
				"/app/assets/media/icon.png",
				"/app/assets/media/assets/icon.png",
				"/app/assets/media/assets/images/icon.png",
				"/media/icon.png",
			},
		},
	}

	for _, test := range tests {
		for i, p := range test.matchedPaths {
			if !MatchPathBasedACL(test.pattern, p) {
				t.Logf("FAIL: Test %d, path: %s, pattern: %s, expected to succeed but failed", i, p, test.pattern)
				testFailed++
				continue
			}
			t.Logf("PASS: Test %d, path: %s, pattern: %s, expected to succeed and succeeded", i, p, test.pattern)
		}
		for i, p := range test.mismatchedPaths {
			if MatchPathBasedACL(test.pattern, p) {
				t.Logf("FAIL: Test %d, path: %s, pattern: %s, expected to fail but succeeded", i, p, test.pattern)
				testFailed++
				continue
			}
			t.Logf("PASS: Test %d, path: %s, pattern: %s, expected to fail and failed", i, p, test.pattern)
		}
	}

	if testFailed > 0 {
		t.Fatalf("Failed %d tests", testFailed)
	}
}
