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

package kms

import (
	"fmt"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/caddy-auth-jwt/internal/tests"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"os"
	"testing"
)

func TestValidateCryptoKeyConfig(t *testing.T) {
	var testcases = []struct {
		name      string
		config    *CryptoKeyConfig
		shouldErr bool
		err       error
	}{
		{
			name: "default shared key in default context for verify",
			config: &CryptoKeyConfig{
				ID:            "0",
				Usage:         "verify",
				TokenName:     "foobar token",
				Source:        "config",
				Algorithm:     "hmac",
				Secret:        "foobar",
				TokenLifetime: 900,
				parsed:        true,
			},
		},
		{
			name: "invalid key usage",
			config: &CryptoKeyConfig{
				ID:            "0",
				Usage:         "both",
				TokenName:     "foobar token",
				Source:        "config",
				Algorithm:     "hmac",
				Secret:        "foobar",
				TokenLifetime: 900,
				parsed:        true,
			},
			shouldErr: true,
			err:       fmt.Errorf("key usage %q is invalid", "both"),
		},
		{
			name: "empty key usage",
			config: &CryptoKeyConfig{
				ID:            "0",
				TokenName:     "foobar token",
				Source:        "config",
				Algorithm:     "hmac",
				Secret:        "foobar",
				TokenLifetime: 900,
				parsed:        true,
			},
			shouldErr: true,
			err:       fmt.Errorf("key usage is not set"),
		},
		{
			name: "invalid key source",
			config: &CryptoKeyConfig{
				ID:            "0",
				Usage:         "verify",
				TokenName:     "foobar token",
				Source:        "foo",
				Algorithm:     "hmac",
				Secret:        "foobar",
				TokenLifetime: 900,
				parsed:        true,
			},
			shouldErr: true,
			err:       fmt.Errorf("key source %q is invalid", "foo"),
		},
		{
			name: "empty key source",
			config: &CryptoKeyConfig{
				ID:            "0",
				Usage:         "verify",
				TokenName:     "foobar token",
				Algorithm:     "hmac",
				Secret:        "foobar",
				TokenLifetime: 900,
				parsed:        true,
			},
			shouldErr: true,
			err:       fmt.Errorf("key source not found"),
		},
		{
			name: "invalid key algo",
			config: &CryptoKeyConfig{
				ID:            "0",
				Usage:         "verify",
				TokenName:     "foobar token",
				Source:        "config",
				Algorithm:     "foo",
				Secret:        "foobar",
				TokenLifetime: 900,
				parsed:        true,
			},
			shouldErr: true,
			err:       fmt.Errorf("key algorithm %q is invalid", "foo"),
		},
		{
			name: "empty source type for env",
			config: &CryptoKeyConfig{
				ID:            "cb315f43c868",
				Usage:         "verify",
				Source:        "env",
				EnvVarName:    "JWT_SECRET_KEY",
				TokenName:     "access_token",
				TokenLifetime: 900,
				parsed:        true,
				validated:     true,
			},
			shouldErr: true,
			err:       fmt.Errorf("key source type for env not set"),
		},
		{
			name: "invalid source type for env",
			config: &CryptoKeyConfig{
				ID:            "cb315f43c868",
				Usage:         "verify",
				Source:        "env",
				EnvVarName:    "JWT_SECRET_KEY",
				EnvVarType:    "foo",
				TokenName:     "access_token",
				TokenLifetime: 900,
				parsed:        true,
				validated:     true,
			},
			shouldErr: true,
			err:       fmt.Errorf("key source type %q for env is invalid", "foo"),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("config: %v", tc.config))
			err := tc.config.validate()
			if tests.EvalErrWithLog(t, err, nil, tc.shouldErr, tc.err, msgs) {
				return
			}
		})
	}
}

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
			name: "default shared key in default context for verify",
			config: `
			    crypto default token lifetime 2400
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
						TokenLifetime: 2400,
						parsed:        true,
						validated:     true,
					},
				},
			},
		},
		{
			name: "default shared key in default context for both sign and verify",
			config: `
                crypto key token name "foobar token"
                crypto key token lifetime 1800
                crypto key sign-verify foobar
            `,
			want: map[string]interface{}{
				"config_count": 1,
				"configs": []*CryptoKeyConfig{
					{
						ID:            "0",
						Usage:         "sign-verify",
						TokenName:     "foobar token",
						Source:        "config",
						Algorithm:     "hmac",
						Secret:        "foobar",
						TokenLifetime: 1800,
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
                crypto key sign foobar
                crypto key sign barfoo
            `,
			shouldErr: true,
			err: errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(
				`crypto key sign barfoo`,
				`duplicate key id`,
			),
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
			name: "load private-public key pair from separate file paths",
			config: `
                crypto key k9738a405e99 sign from file ./../../testdata/rskeys/test_2_pri.pem
                crypto key k9738a405e99 verify from file ./../../testdata/rskeys/test_2_pub.pem
            `,
			want: map[string]interface{}{
				"config_count": 2,
				"configs": []*CryptoKeyConfig{
					{
						ID:            "k9738a405e99",
						Usage:         "sign",
						TokenName:     "access_token",
						Source:        "config",
						FilePath:      "./../../testdata/rskeys/test_2_pri.pem",
						TokenLifetime: 900,
						parsed:        true,
						validated:     true,
					},
					{
						Seq:           1,
						ID:            "k9738a405e99",
						Usage:         "verify",
						TokenName:     "access_token",
						Source:        "config",
						FilePath:      "./../../testdata/rskeys/test_2_pub.pem",
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
			name: "empty env variable value",
			config: `
                crypto key cb315f43c868 verify from env JWT_SHARED_SECRET
            `,
			env: map[string]string{
				"JWT_SHARED_SECRET": "     ",
			},
			shouldErr: true,
			err: errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(
				"crypto key cb315f43c868 verify from env JWT_SHARED_SECRET",
				errors.ErrCryptoKeyConfigEmptyEnvVar.WithArgs("JWT_SHARED_SECRET"),
			),
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
		{
			name: "config entry is too short",
			config: `
                crypto key
            `,
			shouldErr: true,
			err: errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(
				"crypto key", "entry is too short",
			),
		},
		{
			name: "config entry without closing quote",
			config: `
                crypto key "foo
            `,
			shouldErr: true,
			err: errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(
				`crypto key "foo`,
				`record on line 1; parse error on line 2, column 0: extraneous or missing " in quoted-field`,
			),
		},
		{
			name: "config entry with invalid default token setting",
			config: `
                crypto default token foo bar
            `,
			shouldErr: true,
			err: errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(
				`crypto default token foo bar`,
				`unknown default token setting`,
			),
		},
		{
			name: "config entry with too short default token setting",
			config: `
                crypto default token lifetime
            `,
			shouldErr: true,
			err: errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(
				`crypto default token lifetime`,
				`default token setting too short`,
			),
		},
		{
			name: "config entry with invalid default token lifetime",
			config: `
                crypto default token lifetime abc123
            `,
			shouldErr: true,
			err: errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(
				`crypto default token lifetime abc123`,
				`strconv.Atoi: parsing "abc123": invalid syntax`,
			),
		},
		{
			name: "config entry with unknown default setting",
			config: `
                crypto default foo bar foobar
            `,
			shouldErr: true,
			err: errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(
				`crypto default foo bar foobar`,
				`unknown default setting`,
			),
		},
		{
			name: "invalid config entry",
			config: `
                crypto foo bar foo bar
            `,
			shouldErr: true,
			err: errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(
				`crypto foo bar foo bar`,
				`bad syntax`,
			),
		},
		{
			name: "bad key token syntax",
			config: `
			    crypto key 123 verify foobar
                crypto key 123 token foo
            `,
			shouldErr: true,
			err: errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(
				`crypto key 123 token foo`,
				`token must be followed by its attributes`,
			),
		},
		{
			name: "reserved keyword must not be last",
			config: `
                crypto key 123 verify foobar
                crypto key 123 token
            `,
			shouldErr: true,
			err: errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(
				`crypto key 123 token`,
				`reserved keyword must not be last`,
			),
		},
		{
			name: "key with invalid token lifetime",
			config: `
                crypto key 123 verify foobar
                crypto key 123 token lifetime abc123
            `,
			shouldErr: true,
			err: errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(
				`crypto key 123 token lifetime abc123`,
				`strconv.Atoi: parsing "abc123": invalid syntax`,
			),
		},
		{
			name: "key with unknown key token setting",
			config: `
                crypto key 123 verify foobar
                crypto key 123 token foo bar
            `,
			shouldErr: true,
			err: errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(
				`crypto key 123 token foo bar`,
				`unknown key token setting`,
			),
		},
		{
			name: "key with usage with bad syntax",
			config: `
                crypto key 123 verify foo bar 
            `,
			shouldErr: true,
			err: errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(
				`crypto key 123 verify foo bar`,
				`bad syntax`,
			),
		},
		{
			name: "bad syntax",
			config: `
                crypto key 123 verify foo bar
            `,
			shouldErr: true,
			err: errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(
				`crypto key 123 verify foo bar`,
				`bad syntax`,
			),
		},
		{
			name: "invalid from config",
			config: `
                crypto key 123 verify from foo /path/to/file
		    `,
			shouldErr: true,
			err: errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(
				`crypto key 123 verify from foo /path/to/file`,
				`bad syntax`,
			),
		},
		{
			name: "invalid from env",
			config: `
                crypto key 123 verify from env JWT_SECRET_FILE as foo
            `,
			shouldErr: true,
			err: errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(
				`crypto key 123 verify from env JWT_SECRET_FILE as foo`,
				`bad syntax`,
			),
		},
		{
			name: "invalid from env as",
			config: `
                crypto key 123 verify from env JWT_SECRET_FILE foo bar
            `,
			shouldErr: true,
			err: errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(
				`crypto key 123 verify from env JWT_SECRET_FILE foo bar`,
				`bad syntax`,
			),
		},
		{
			name: "invalid from env as file and empty env var",
			config: `
                crypto key 123 verify from env JWT_SECRET_FILE as file
            `,
			shouldErr: true,
			err: errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(
				`crypto key 123 verify from env JWT_SECRET_FILE as file`,
				`environment variable JWT_SECRET_FILE has empty value`,
			),
		},
		{
			name: "invalid from env as file and too long",
			config: `
                crypto key 123 verify from env JWT_SECRET_FILE as file foo
            `,
			shouldErr: true,
			err: errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(
				`crypto key 123 verify from env JWT_SECRET_FILE as file foo`,
				`bad syntax`,
			),
		},
		{
			name: "invalid key argument",
			config: `
                crypto key 123 foo foo foo foo foo
            `,
			shouldErr: true,
			err: errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(
				`crypto key 123 foo foo foo foo foo`,
				`invalid argument`,
			),
		},
		{
			name: "without key configs",
			config: `
                crypto default token name foo
            `,
			shouldErr: true,
			err:       errors.ErrCryptoKeyConfigNoConfigFound,
		},
		{
			name: "with validate error",
			config: `
                crypto key 123 token name foo
            `,
			shouldErr: true,
			err:       errors.ErrCryptoKeyConfigKeyInvalid.WithArgs(0, "key usage is not set"),
		},
		{
			name: "load mix static and private keys",
			config: `
                crypto key token name usertoken
                crypto key verify foobar
                crypto key k9738a405e99 verify from file ./../../testdata/rskeys/test_2_pub.pem
            `,
			want: map[string]interface{}{
				"config_count": 2,
				"configs": []*CryptoKeyConfig{
					{
						ID:            "0",
						Usage:         "verify",
						TokenName:     "usertoken",
						Source:        "config",
						Algorithm:     "hmac",
						TokenLifetime: 900,
						Secret:        "foobar",
						parsed:        true,
						validated:     true,
					},
					{
						ID:            "k9738a405e99",
						Seq:           1,
						Usage:         "verify",
						TokenName:     "access_token",
						Source:        "config",
						FilePath:      "./../../testdata/rskeys/test_2_pub.pem",
						TokenLifetime: 900,
						parsed:        true,
						validated:     true,
					},
				},
			},
		},
		{
			name: "load mix static and private keys with default token name",
			config: `
				crypto default token name usertoken
                crypto key verify foobar
                crypto key k9738a405e99 verify from file ./../../testdata/rskeys/test_2_pub.pem
            `,
			want: map[string]interface{}{
				"config_count": 2,
				"configs": []*CryptoKeyConfig{
					{
						ID:            "0",
						Usage:         "verify",
						TokenName:     "usertoken",
						Source:        "config",
						Algorithm:     "hmac",
						TokenLifetime: 900,
						Secret:        "foobar",
						parsed:        true,
						validated:     true,
					},
					{
						ID:            "k9738a405e99",
						Seq:           1,
						Usage:         "verify",
						TokenName:     "usertoken",
						Source:        "config",
						FilePath:      "./../../testdata/rskeys/test_2_pub.pem",
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
			configs, err := ParseCryptoKeyConfigs(tc.config)
			if tests.EvalErrWithLog(t, err, nil, tc.shouldErr, tc.err, msgs) {
				return
			}
			got := make(map[string]interface{})
			got["config_count"] = len(configs)
			got["configs"] = configs

			for i, c := range configs {
				msgs = append(msgs, fmt.Sprintf("config %d: %s", i, c.ToString()))
			}

			if diff := cmp.Diff(tc.want, got, cmp.AllowUnexported(CryptoKeyConfig{})); diff != "" {
				tests.WriteLog(t, msgs)
				t.Fatalf("output mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
