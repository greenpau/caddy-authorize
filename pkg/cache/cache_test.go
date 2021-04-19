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

package cache

import (
	"github.com/greenpau/caddy-auth-jwt/pkg/testutils"
	"testing"
	"time"
)

func TestTokenCache(t *testing.T) {
	userClaims := testutils.NewTestUserClaims()
	signingKey := testutils.NewTestSigningKey()
	token, err := signingKey.SignToken(nil, userClaims)
	if err != nil {
		t.Fatalf("Failed to get JWT token for %v: %v", userClaims, err)
	}

	// t.Logf("Token: %s", token)
	//	t.Logf("Claims: %v", userClaims)

	c := NewTokenCache()
	// t.Logf("Token cache contains %d entries", len(c.Entries))

	c.Add(token, *userClaims)
	if len(c.Entries) != 1 {
		t.Fatalf("Token cache contains %d entries, not the expected 1 entry", len(c.Entries))
	}
	// t.Logf("Token cache contains %d entries", len(c.Entries))

	cachedClaims := c.Get(token)
	if cachedClaims == nil {
		t.Fatalf("Token cache did not return previously cached userClaims")
	}

	// t.Logf("Cached Claims: %v", userClaims)

	c.Delete(token)
	if len(c.Entries) != 0 {
		t.Fatalf("Token cache contains %d entries, not the expected 0 entries", len(c.Entries))
	}

	userClaims = testutils.NewTestUserClaims()
	userClaims.ExpiresAt = time.Now().Add(time.Duration(-900) * time.Second).Unix()
	token, err = signingKey.SignToken(nil, userClaims)
	if err != nil {
		t.Fatalf("Failed to get JWT token for %v: %v", userClaims, err)
	}
	c.Add(token, *userClaims)
	if len(c.Entries) != 1 {
		t.Fatalf("Token cache contains %d entries, not the expected 1 entry", len(c.Entries))
	}
	// t.Logf("Token cache contains %d entries", len(c.Entries))
	cachedClaims = c.Get(token)
	if cachedClaims != nil {
		t.Fatalf("Token cache returned previously cached expired userClaims")
	}
	if len(c.Entries) != 0 {
		t.Fatalf("Token cache contains %d entries, not the expected 0 entries", len(c.Entries))
	}

	// t.Logf("Passed")
}
