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
	"github.com/greenpau/caddy-auth-jwt/pkg/user"
	"github.com/greenpau/caddy-auth-jwt/pkg/utils"
	"os"
	"testing"
	"time"
)

func newTestUser() *user.User {
	cfg := `{
        "exp": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix()) + `,
        "iat": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute*-1).Unix()) + `,
        "nbf": ` + fmt.Sprintf("%d", time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix()) + `,
        "name":   "Smith, John",
        "email":  "smithj@outlook.com",
        "origin": "localhost",
        "sub":    "smithj@outlook.com",
        "roles": "anonymous guest"
    }`
	usr, err := user.NewUser(cfg)
	if err != nil {
		panic(err)
	}
	return usr
}

func TestSignToken(t *testing.T) {
	testcases := []struct {
		name                string
		claims              string
		cryptoKeyConfig     interface{}
		mandatorySignMethod interface{}
		err                 error
		shouldErr           bool
	}{
		{
			name: "valid HS256 token",
			claims: `{
                "addr": "10.0.2.2",
                "authenticated": true,
                "exp": 1613327613,
                "iat": 1613324013,
                "iss": "https://localhost:8443/auth",
                "jti": "a9d73486-b647-472a-b380-bea33a6115af",
                "mail": "webadmin@localdomain.local",
                "origin": "localhost",
                "roles": ["superadmin", "guest", "anonymous"],
                "sub": "jsmith"
            }`,
			cryptoKeyConfig: `{
                "token_secret": "e2c52192-261f-4e8f-ab83-c8eb928a8ddb",
                "token_name": "jwt_access_token",
                "token_lifetime": 1800
            }`,
		},
		{
			name:   "invalid sign method TB123",
			claims: fmt.Sprintf(`{"exp":%d}`, time.Now().Add(10*time.Minute).Unix()),
			cryptoKeyConfig: `{
                "token_secret": "e2c52192-261f-4e8f-ab83-c8eb928a8ddb",
                "token_name": "secure_token",
                "token_lifetime": 600
            }`,
			mandatorySignMethod: "TB123",
			shouldErr:           true,
			err:                 errors.ErrUnsupportedSigningMethod.WithArgs("TB123"),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var msgs []string
			msgs = append(msgs, fmt.Sprintf("test name: %s", tc.name))

			cryptoKeyConfig, err := NewCryptoKeyConfig(tc.cryptoKeyConfig)
			if err != nil {
				t.Fatal(err)
			}
			usr, err := user.NewUser(tc.claims)
			if err != nil {
				t.Fatalf("NewUser() failed: %v", err)
			}
			msgs = append(msgs, fmt.Sprintf("user claims: %v", usr.GetData()))
			var k *Key
			km, err := NewKeyManager(cryptoKeyConfig)
			_, keys := km.GetKeys()
			for _, entry := range keys {
				k = entry
				break
			}
			err = k.SignToken(tc.mandatorySignMethod, usr)
			tests.EvalErrWithLog(t, err, "signed token", tc.shouldErr, tc.err, msgs)
		})
	}
}

func TestGetKeysFromConfig(t *testing.T) {
	var testcases = []struct {
		name     string
		disabled bool
		config   string
		env      map[string]string
		want     map[string]interface{}
		// keyPair indicates which keys are being used for sign/verification.
		keyPair   []int
		shouldErr bool
		err       error
	}{
		{
			disabled: true,
			name:     "default shared key in default context",
			config: `
                crypto key token name "foobar token"
                crypto key both foobar
            `,
			keyPair: []int{0, 0},
			want: map[string]interface{}{
				"config_count": 1,
				"key_count":    1,
			},
		},
		{
			disabled: true,
			name:     "shared secret embedded in environment variable",
			config: `
                crypto key cb315f43c868 both from env JWT_SHARED_SECRET
            `,
			env: map[string]string{
				"JWT_TOKEN_LIFETIME": "3600",
				"JWT_SHARED_SECRET":  "foobar",
			},
			keyPair: []int{0, 0},
			want: map[string]interface{}{
				"config_count": 1,
				"key_count":    1,
			},
		},
		{
			name: "load private and public rsa keys from file path",
			config: `
                crypto key k9738a405e99 sign from file ./../../testdata/rskeys/test_2_pri.pem
                crypto key k9738a405e99 verify from file ./../../testdata/rskeys/test_2_pub.pem
            `,
			keyPair: []int{0, 1},
			want: map[string]interface{}{
				"config_count": 2,
				"key_count":    2,
				"key_sign":     true,
				"key_verify":   true,
			},
		},
		/*
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
						err:       errors.ErrCryptoKeyConfigMultipleDefaultKeys,
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
								},
							},
						},
					},
					{
						name: "load key from the value in JWT_SECRET_KEY environment variable",
						config: `
			                crypto key cb315f43c868 verify from env JWT_SECRET_FILE as key
			            `,
						want: map[string]interface{}{
							"config_count": 1,
							"configs": []*CryptoKeyConfig{
								{
									ID:            "cb315f43c868",
									Usage:         "verify",
									Source:        "env",
									EnvVarName:    "JWT_SECRET_FILE",
									EnvVarType:    "key",
									TokenName:     "access_token",
									TokenLifetime: 900,
								},
							},
						},
					},
					{
						name: "load key from the file named in JWT_SECRET_FILE environment variable",
						config: `
			                crypto key cb315f43c868 verify from env JWT_SECRET_FILE as file
			            `,
						want: map[string]interface{}{
							"config_count": 1,
							"configs": []*CryptoKeyConfig{
								{
									ID:            "cb315f43c868",
									Usage:         "verify",
									Source:        "env",
									EnvVarName:    "JWT_SECRET_FILE",
									EnvVarType:    "file",
									TokenName:     "access_token",
									TokenLifetime: 900,
								},
							},
						},
					},
					{
						name: "load keys from the files in the directory named in JWT_SECRET_DIR environment variable",
						config: `
			                crypto key cb315f43c868 verify from env JWT_SECRET_DIR as directory
			            `,
						want: map[string]interface{}{
							"config_count": 1,
							"configs": []*CryptoKeyConfig{
								{
									ID:            "cb315f43c868",
									Usage:         "verify",
									Source:        "env",
									EnvVarName:    "JWT_SECRET_DIR",
									EnvVarType:    "directory",
									TokenName:     "access_token",
									TokenLifetime: 900,
								},
							},
						},
					},
		*/
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.disabled {
				return
			}
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("config: %s", tc.config))
			for k, v := range tc.env {
				msgs = append(msgs, fmt.Sprintf("env: %s = %s", k, v))
				os.Setenv(k, v)
				defer os.Unsetenv(k)
			}

			logger := utils.NewLogger()
			configs, err := ParseCryptoKeyConfigs(tc.config, logger)
			if err != nil {
				t.Fatal(err)
			}

			for _, c := range configs {
				t.Logf("%s", c.ToString())
			}

			keys, err := GetKeysFromConfigs(configs)
			if tests.EvalErrWithLog(t, err, "keys", tc.shouldErr, tc.err, msgs) {
				return
			}

			var privKey, pubKey *CryptoKey

			got := make(map[string]interface{})
			got["config_count"] = len(configs)
			got["key_count"] = len(keys)

			t.Logf("crypto configs:\n%s", cmp.Diff(nil, configs))
			t.Logf("crypto keys:\n%s", cmp.Diff(nil, keys))

			if len(tc.keyPair) == 2 {
				for i, key := range keys {
					switch i {
					case tc.keyPair[0]:
						privKey = key
					case tc.keyPair[1]:
						pubKey = key
					}
				}
				t.Logf("crypto private key:\n%s", cmp.Diff(nil, privKey))
				t.Logf("crypto public key:\n%s", cmp.Diff(nil, pubKey))
			}

			for _, k := range []string{"key_sign", "key_verify"} {
				if _, exists := tc.want[k]; !exists {
					continue
				}
				switch k {
				case "key_sign":
					got[k] = privKey.Sign.Capable
				case "key_verify":
					got[k] = pubKey.Verify.Capable
				}
			}

			if diff := cmp.Diff(tc.want, got, cmp.AllowUnexported(CryptoKeyConfig{})); diff != "" {
				tests.WriteLog(t, msgs)
				t.Fatalf("output mismatch (-want +got):\n%s", diff)
			}

			if privKey == nil || pubKey == nil {
				return
			}

			ks := NewCryptoKeyStore()
			if err := ks.AddKeys(keys); err != nil {
				t.Fatal(err)
			}
			usr := newTestUser()
			t.Logf("%v", usr)

			if err := ks.SignToken(privKey.Sign.Token.Name, privKey.Sign.Token.DefaultMethod, usr); err != nil {
				t.Fatal(err)
			}

			t.Logf("token %v: %s", privKey.Sign.Token.Name, usr.Token)

			tokenUser, err := ks.ParseToken(pubKey.Verify.Token.Name, usr.Token)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("user:\n%s", cmp.Diff(nil, tokenUser))

		})
	}
}
