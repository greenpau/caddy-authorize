// Copyright 2020 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cache

import (
	"fmt"
	"github.com/greenpau/caddy-auth-jwt/internal/tests"
	"github.com/greenpau/caddy-auth-jwt/internal/testutils"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"testing"
	"time"
)

func TestTokenCache(t *testing.T) {
	c := NewTokenCache(100)
	d := NewTokenCache(0)

	testcases := []struct {
		name              string
		delay             int
		deletedByManager  bool
		emptyUser         bool
		emptyToken        bool
		emptyCache        bool
		emptyCacheEntries bool
		err               error
		shouldErr         bool
	}{
		{
			name: "valid token",
		},
		{
			name:      "get expired token",
			delay:     -900,
			shouldErr: true,
			err:       fmt.Errorf("token expired"),
		},
		{
			name:             "expired token deleted by cache manager",
			deletedByManager: true,
			shouldErr:        true,
			err:              fmt.Errorf("no user found"),
		},
		{
			name:      "nil user",
			emptyUser: true,
			shouldErr: true,
			err:       errors.ErrCacheNilUser,
		},
		{
			name:       "empty token",
			emptyToken: true,
			shouldErr:  true,
			err:        errors.ErrCacheEmptyToken,
		},
		{
			name:              "cache entries is nil",
			emptyCacheEntries: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var msgs []string
			msgs = append(msgs, fmt.Sprintf("test name: %s", tc.name))
			usr := testutils.NewTestUser()
			ks := testutils.NewTestCryptoKeyStore()
			err := ks.SignToken("access_token", "HS512", usr)
			if tc.emptyToken {
				usr.Token = ""
			}
			if tc.emptyUser {
				usr = nil
			}
			err = c.Add(usr)
			d.Add(usr)
			if tc.delay == 0 && !tc.deletedByManager {
				if tests.EvalErrWithLog(t, err, "signed token", tc.shouldErr, tc.err, msgs) {
					return
				}
			}

			if tc.deletedByManager {
				usr.Claims.ExpiresAt = time.Now().Add(time.Duration(-1000) * time.Second).Unix()
			}

			if tc.emptyCacheEntries {
				c.Entries = nil
			}

			time.Sleep(time.Millisecond * time.Duration(200))

			if tc.emptyCacheEntries {
				return
			}

			switch {
			case tc.delay < 0:
				usr.Claims.ExpiresAt = time.Now().Add(time.Duration(tc.delay) * time.Second).Unix()
				if c.Get(usr.Token) == nil {
					err = fmt.Errorf("token expired")
				}
			case tc.deletedByManager:
				if c.Get(usr.Token) == nil {
					err = fmt.Errorf("no user found")
				}
			default:
				if c.Get(usr.Token) == nil {
					err = fmt.Errorf("token expired")
				}
			}

			if c.Get("foobar") != nil {
				err = fmt.Errorf("got user for invalid token")
			}

			if tests.EvalErrWithLog(t, err, "cache", tc.shouldErr, tc.err, msgs) {
				return
			}
		})
	}
}
