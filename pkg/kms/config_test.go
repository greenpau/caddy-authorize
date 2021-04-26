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
	"fmt"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"github.com/greenpau/caddy-auth-jwt/pkg/tests"
	"github.com/greenpau/caddy-auth-jwt/pkg/utils"
	"os"
	"testing"
)

func TestParseCryptoKeyConfigs(t *testing.T) {
	var testcases = []struct {
		name      string
		config    string
		env       map[string]string
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name: "default shared key in default context",
			config: `
                crypto key token name "foobar token"
                crypto key verify foobar
            `,
			want: map[string]interface{}{
				"config_count": 1,
				"configs": []*CryptoKeyConfig{
					{
						ID:            "0",
						Usage:         "verify",
						TokenName:     "foobar token",
						Source:        "config",
						Algorithm:     "hmac",
						Secret:        "foobar",
						TokenLifetime: 900,
						parsed:        true,
						validated:     true,
					},
				},
			},
		},
		{
			name: "multiple shared keys in default context",
			config: `
                crypto key token name "foobar token"
                crypto key verify foobar
                crypto key abc123 token name foobar_token
                crypto key abc123 verify foobar
            `,
			want: map[string]interface{}{
				"config_count": 2,
				"configs": []*CryptoKeyConfig{
					{
						ID:            "0",
						Usage:         "verify",
						TokenName:     "foobar token",
						Source:        "config",
						Algorithm:     "hmac",
						Secret:        "foobar",
						TokenLifetime: 900,
						parsed:        true,
						validated:     true,
					},
					{
						Seq:           1,
						ID:            "abc123",
						Usage:         "verify",
						TokenName:     "foobar_token",
						Source:        "config",
						Algorithm:     "hmac",
						Secret:        "foobar",
						TokenLifetime: 900,
						parsed:        true,
						validated:     true,
					},
				},
			},
		},
		{
			name: "multiple shared keys in with implicit token name config",
			config: `
                crypto key verify foobar
                crypto key abc123 verify foobar
            `,
			want: map[string]interface{}{
				"config_count": 2,
				"configs": []*CryptoKeyConfig{
					{
						ID:            "0",
						Usage:         "verify",
						Source:        "config",
						Algorithm:     "hmac",
						Secret:        "foobar",
						TokenName:     "access_token",
						TokenLifetime: 900,
						parsed:        true,
						validated:     true,
					},
					{
						Seq:           1,
						ID:            "abc123",
						Usage:         "verify",
						Source:        "config",
						Algorithm:     "hmac",
						Secret:        "foobar",
						TokenName:     "access_token",
						TokenLifetime: 900,
						parsed:        true,
						validated:     true,
					},
				},
			},
		},
		{
			name: "multiple shared keys in with explicit default token name config",
			config: `
                crypto default token name jwt_token
                crypto key verify foobar
                crypto key abc123 verify foobar
                crypto key abc123 token name foobar_token
            `,
			want: map[string]interface{}{
				"config_count": 2,
				"configs": []*CryptoKeyConfig{
					{
						ID:            "0",
						Usage:         "verify",
						Source:        "config",
						Algorithm:     "hmac",
						Secret:        "foobar",
						TokenName:     "jwt_token",
						TokenLifetime: 900,
						parsed:        true,
						validated:     true,
					},
					{
						Seq:           1,
						ID:            "abc123",
						Usage:         "verify",
						TokenName:     "foobar_token",
						Source:        "config",
						Algorithm:     "hmac",
						Secret:        "foobar",
						TokenLifetime: 900,
						parsed:        true,
						validated:     true,
					},
				},
			},
		},
		{
			name: "single default shared key",
			config: `
                crypto key verify foobar
            `,
			want: map[string]interface{}{
				"config_count": 1,
				"configs": []*CryptoKeyConfig{
					{
						ID:            "0",
						Usage:         "verify",
						Source:        "config",
						Algorithm:     "hmac",
						Secret:        "foobar",
						TokenName:     "access_token",
						TokenLifetime: 900,
						parsed:        true,
						validated:     true,
					},
				},
			},
		},
		{
			name: "multiple default shared keys",
			config: `
                crypto key verify foobar
                crypto key verify barfoo
            `,
			shouldErr: true,
			err:       fmt.Errorf("key config entry %q contains duplicate key id", "crypto key verify barfoo"),
		},
		{
			name: "load key from file path",
			config: `
                crypto key k9738a405e99 verify from file /path/to/file
            `,
			want: map[string]interface{}{
				"config_count": 1,
				"configs": []*CryptoKeyConfig{
					{
						ID:            "k9738a405e99",
						Usage:         "verify",
						Source:        "config",
						FilePath:      "/path/to/file",
						TokenName:     "access_token",
						TokenLifetime: 900,
						parsed:        true,
						validated:     true,
					},
				},
			},
		},
		{
			name: "load keys from directory path",
			config: `
                crypto key k9738a405e99 verify from directory /path/to/dir
            `,
			want: map[string]interface{}{
				"config_count": 1,
				"configs": []*CryptoKeyConfig{
					{
						ID:            "k9738a405e99",
						Usage:         "verify",
						Source:        "config",
						DirPath:       "/path/to/dir",
						TokenName:     "access_token",
						TokenLifetime: 900,
						parsed:        true,
						validated:     true,
					},
				},
			},
		},
		{
			name: "shared secret embedded in environment variable",
			config: `
                crypto key cb315f43c868 verify from env JWT_SHARED_SECRET
            `,
			env: map[string]string{
				"JWT_SHARED_SECRET": "foobar",
			},
			want: map[string]interface{}{
				"config_count": 1,
				"configs": []*CryptoKeyConfig{
					{
						ID:            "cb315f43c868",
						Usage:         "verify",
						Source:        "env",
						EnvVarName:    "JWT_SHARED_SECRET",
						EnvVarValue:   "foobar",
						EnvVarType:    "key",
						TokenName:     "access_token",
						TokenLifetime: 900,
						parsed:        true,
						validated:     true,
					},
				},
			},
		},
		{
			name: "load key from the value in JWT_SECRET_KEY environment variable",
			config: `
                crypto key cb315f43c868 verify from env JWT_SECRET_KEY as key
            `,
			env: map[string]string{
				"JWT_SECRET_KEY": "----BEGIN RSA ...",
			},
			want: map[string]interface{}{
				"config_count": 1,
				"configs": []*CryptoKeyConfig{
					{
						ID:            "cb315f43c868",
						Usage:         "verify",
						Source:        "env",
						EnvVarName:    "JWT_SECRET_KEY",
						EnvVarValue:   "----BEGIN RSA ...",
						EnvVarType:    "key",
						TokenName:     "access_token",
						TokenLifetime: 900,
						parsed:        true,
						validated:     true,
					},
				},
			},
		},
		{
			name: "load key from the file named in JWT_SECRET_FILE environment variable",
			config: `
                crypto key cb315f43c868 verify from env JWT_SECRET_FILE as file
            `,
			env: map[string]string{
				"JWT_SECRET_FILE": "/path/to/file",
			},
			want: map[string]interface{}{
				"config_count": 1,
				"configs": []*CryptoKeyConfig{
					{
						ID:            "cb315f43c868",
						Usage:         "verify",
						Source:        "env",
						EnvVarName:    "JWT_SECRET_FILE",
						EnvVarValue:   "/path/to/file",
						EnvVarType:    "file",
						TokenName:     "access_token",
						TokenLifetime: 900,
						parsed:        true,
						validated:     true,
					},
				},
			},
		},
		{
			name: "load keys from the files in the directory named in JWT_SECRET_DIR environment variable",
			config: `
                crypto key cb315f43c868 verify from env JWT_SECRET_DIR as directory
            `,
			env: map[string]string{
				"JWT_SECRET_DIR": "/path/to/dir",
			},
			want: map[string]interface{}{
				"config_count": 1,
				"configs": []*CryptoKeyConfig{
					{
						ID:            "cb315f43c868",
						Usage:         "verify",
						Source:        "env",
						EnvVarName:    "JWT_SECRET_DIR",
						EnvVarValue:   "/path/to/dir",
						EnvVarType:    "directory",
						TokenName:     "access_token",
						TokenLifetime: 900,
						parsed:        true,
						validated:     true,
					},
				},
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("config: %s", tc.config))
			for k, v := range tc.env {
				msgs = append(msgs, fmt.Sprintf("env: %s = %s", k, v))
				os.Setenv(k, v)
				defer os.Unsetenv(k)
			}
			logger := utils.NewLogger()
			configs, err := ParseCryptoKeyConfigs(tc.config, logger)
			if tests.EvalErrWithLog(t, err, nil, tc.shouldErr, tc.err, msgs) {
				return
			}
			got := make(map[string]interface{})
			got["config_count"] = len(configs)
			got["configs"] = configs

			if diff := cmp.Diff(tc.want, got, cmp.AllowUnexported(CryptoKeyConfig{})); diff != "" {
				tests.WriteLog(t, msgs)
				t.Fatalf("output mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNewCryptoKeyConfig(t *testing.T) {
	testcases := []struct {
		name      string
		configure func() (*CryptoKeyConfig, error)
		err       error
		shouldErr bool
	}{
		{
			name: "json string input",
			configure: func() (*CryptoKeyConfig, error) {
				return NewCryptoKeyConfig(`{
					"token_secret": "e2c52192-261f-4e8f-ab83-c8eb928a8ddb",
		            "token_name": "jwt_access_token",
			        "token_lifetime": 1800
				}`)
			},
		},
		{
			name: "empty string input",
			configure: func() (*CryptoKeyConfig, error) {
				return NewCryptoKeyConfig("")
			},
			shouldErr: true,
			err:       errors.ErrCryptoKeyConfigNewEmptyArg,
		},
		{
			name: "malformed json input",
			configure: func() (*CryptoKeyConfig, error) {
				return NewCryptoKeyConfig(`{`)
			},
			shouldErr: true,
			err:       errors.ErrCryptoKeyConfigNewFailedUnmarshal.WithArgs("unexpected end of JSON input"),
		},
		{
			name: "json bytes input",
			configure: func() (*CryptoKeyConfig, error) {
				return NewCryptoKeyConfig([]byte(`{
                    "token_secret": "e2c52192-261f-4e8f-ab83-c8eb928a8ddb",
                    "token_name": "jwt_access_token",
                    "token_lifetime": 1800
                }`))
			},
		},
		{
			name: "no arguments",
			configure: func() (*CryptoKeyConfig, error) {
				return NewCryptoKeyConfig()
			},
		},
		{
			name: "nil argument",
			configure: func() (*CryptoKeyConfig, error) {
				return NewCryptoKeyConfig(nil)
			},
			shouldErr: true,
			err:       errors.ErrCryptoKeyConfigNewArgTypeInvalid.WithArgs([]interface{}{nil}),
		},
		{
			name: "invalid argument",
			configure: func() (*CryptoKeyConfig, error) {
				return NewCryptoKeyConfig(2)
			},
			shouldErr: true,
			err:       errors.ErrCryptoKeyConfigNewInvalidArgs.WithArgs([]interface{}{2}),
		},
		{
			name: "too many arguments",
			configure: func() (*CryptoKeyConfig, error) {
				return NewCryptoKeyConfig(1, "foo", "bar", "foo")
			},
			shouldErr: true,
			err:       errors.ErrCryptoKeyConfigNewInvalidArgs.WithArgs([]interface{}{1, "foo", "bar", "foo"}),
		},
		{
			name: "HS512 with valid secret",
			configure: func() (*CryptoKeyConfig, error) {
				return NewCryptoKeyConfig("HS512", "foobar")
			},
		},
		{
			name: "HS512 with invalid secret",
			configure: func() (*CryptoKeyConfig, error) {
				return NewCryptoKeyConfig("HS512", 2)
			},
			shouldErr: true,
			err:       errors.ErrCryptoKeyConfigNewInvalidArgs.WithArgs([]interface{}{"HS512"}),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			cryptoKeyConfig, err := tc.configure()
			tests.EvalErr(t, err, cryptoKeyConfig, tc.shouldErr, tc.err)
		})
	}
}
