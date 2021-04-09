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

package kms

import (
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"github.com/greenpau/caddy-auth-jwt/pkg/tests"
	"testing"
)

func TestNewTokenConfig(t *testing.T) {
	testcases := []struct {
		name      string
		configure func() (*TokenConfig, error)
		err       error
		shouldErr bool
	}{
		{
			name: "json string input",
			configure: func() (*TokenConfig, error) {
				return NewTokenConfig(`{
					"token_secret": "e2c52192-261f-4e8f-ab83-c8eb928a8ddb",
		            "token_name": "jwt_access_token",
			        "token_lifetime": 1800
				}`)
			},
		},
		{
			name: "empty string input",
			configure: func() (*TokenConfig, error) {
				return NewTokenConfig("")
			},
			shouldErr: true,
			err:       errors.ErrTokenConfigNewEmptyArg,
		},
		{
			name: "malformed json input",
			configure: func() (*TokenConfig, error) {
				return NewTokenConfig(`{`)
			},
			shouldErr: true,
			err:       errors.ErrTokenConfigNewFailedUnmarshal.WithArgs("unexpected end of JSON input"),
		},
		{
			name: "json bytes input",
			configure: func() (*TokenConfig, error) {
				return NewTokenConfig([]byte(`{
                    "token_secret": "e2c52192-261f-4e8f-ab83-c8eb928a8ddb",
                    "token_name": "jwt_access_token",
                    "token_lifetime": 1800
                }`))
			},
		},
		{
			name: "no arguments",
			configure: func() (*TokenConfig, error) {
				return NewTokenConfig()
			},
		},
		{
			name: "nil argument",
			configure: func() (*TokenConfig, error) {
				return NewTokenConfig(nil)
			},
			shouldErr: true,
			err:       errors.ErrTokenConfigNewArgTypeInvalid.WithArgs([]interface{}{nil}),
		},
		{
			name: "invalid argument",
			configure: func() (*TokenConfig, error) {
				return NewTokenConfig(2)
			},
			shouldErr: true,
			err:       errors.ErrTokenConfigNewInvalidArgs.WithArgs([]interface{}{2}),
		},
		{
			name: "too many arguments",
			configure: func() (*TokenConfig, error) {
				return NewTokenConfig(1, "foo", "bar", "foo")
			},
			shouldErr: true,
			err:       errors.ErrTokenConfigNewInvalidArgs.WithArgs([]interface{}{1, "foo", "bar", "foo"}),
		},
		{
			name: "HS512 with valid secret",
			configure: func() (*TokenConfig, error) {
				return NewTokenConfig("HS512", "foobar")
			},
		},
		{
			name: "HS512 with invalid secret",
			configure: func() (*TokenConfig, error) {
				return NewTokenConfig("HS512", 2)
			},
			shouldErr: true,
			err:       errors.ErrTokenConfigNewInvalidArgs.WithArgs([]interface{}{"HS512"}),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tokenConfig, err := tc.configure()
			tests.EvalErr(t, err, tokenConfig, tc.shouldErr, tc.err)
		})
	}
}
