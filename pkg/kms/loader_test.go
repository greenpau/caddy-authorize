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
	"encoding/json"
	"fmt"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"github.com/greenpau/caddy-auth-jwt/pkg/tests"
	"os"
	"strings"
	"testing"
)

func TestLoadKeyManager(t *testing.T) {
	dirCWD, err := os.Getwd() // that that we can use a full path
	if err != nil {
		t.Fatal(err)
	}
	var testcases = []struct {
		name          string
		config        string
		env           map[string]string
		tokenLifetime int
		tokenName     string
		keyOrigin     string
		expect        map[string]string
		shouldErr     bool
		err           error
	}{
		{
			name:      "no config or env",
			shouldErr: true,
			err:       errors.ErrEncryptionKeysNotFound,
		},
		{
			name: "parse ECDSA private key with non-PEM file input",
			config: `{
				"token_ecdsa_file": "` + dirCWD + `/../../testdata/misckeys/test_3_empty.pem"
			}`,
			shouldErr: true,
			err:       errors.ErrParsePrivateECDSAKey.WithArgs(errors.ErrNotPEMEncodedKey),
		},
		{
			name: "parse ECDSA private key with PEM-encoded ECDSA public key input",
			config: `{
                "token_ecdsa_file": "` + dirCWD + `/../../testdata/rskeys/test_2_pri.pem"
            }`,
			shouldErr: true,
			err:       errors.ErrParsePrivateECDSAKey.WithArgs("x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)"),
		},

		{
			name:      "mixed methods in env",
			env:       map[string]string{"JWT_RSA_KEY": testPriKey, "JWT_ECDSA_KEY": testEcdsaPriKey},
			shouldErr: true,
			err:       errors.ErrMixedAlgorithms.WithArgs("env", []string{"ecdsa", "rsa"}),
		},
		{
			name: "mixed methods in config",
			config: `{
				"token_rsa_file": "` + dirCWD + `/../../testdata/rskeys/test_1_pri.pem",
				"token_ecdsa_file": "` + dirCWD + `/../../testdata/ecdsakeys/test_1_pri.pem"
			}`,
			shouldErr: true,
			err:       errors.ErrMixedAlgorithms.WithArgs("config", []string{"ecdsa", "rsa"}),
		},
		{
			name: "simple token secret",
			config: `{
				"token_secret": "e2c52192-261f-4e8f-ab83-c8eb928a8ddb",
				"token_name": "jwt_access_token",
				"token_lifetime": 1800
			}`,
			env: map[string]string{
				"JWT_TOKEN_LIFETIME": "3600",
				"JWT_TOKEN_NAME":     "token",
			},
			tokenLifetime: 1800,
			tokenName:     "jwt_access_token",
			expect: map[string]string{
				"0": "string",
			},
		},
		{
			name: "simple env token secret",
			env:  map[string]string{"JWT_TOKEN_SECRET": "e2c52192-261f-4e8f-ab83-c8eb928a8ddb"},
			expect: map[string]string{
				"0": "string",
			},
		},
		{
			name:   "simple config dir",
			config: `{"token_rsa_dir": "./../../testdata/rskeys"}`,
			expect: map[string]string{
				"private":    "*rsa.PrivateKey",
				"test_1_pri": "*rsa.PrivateKey",
				"test_2_pri": "*rsa.PrivateKey",
				"test_2_pub": "*rsa.PublicKey",
			},
		},
		{
			name:   "simple config file",
			config: `{"token_rsa_file": "` + dirCWD + `/../../testdata/rskeys/test_1_pri.pem"}`,
			expect: map[string]string{
				"0": "*rsa.PrivateKey",
			},
		},
		{
			name:   "simple config key",
			config: `{"token_rsa_key": "` + strings.Replace(testPriKey, "\n", "\\n", -1) + `"}`,
			expect: map[string]string{
				"0": "*rsa.PrivateKey",
			},
		},
		{
			name:   "simple config files",
			config: `{"token_rsa_files": {"apple": "./../../testdata/rskeys/test_1_pri.pem"}}`,
			expect: map[string]string{
				"apple": "*rsa.PrivateKey",
			},
		},
		{
			name:   "simple config keys",
			config: `{"token_rsa_keys": {"pear": "` + strings.Replace(testPriKey, "\n", "\\n", -1) + `"}}`,
			expect: map[string]string{
				"pear": "*rsa.PrivateKey",
			},
		},
		{
			name: "simple env dir",
			env:  map[string]string{"JWT_RSA_DIR": "./../../testdata/rskeys"},
			expect: map[string]string{
				"private":    "*rsa.PrivateKey",
				"test_1_pri": "*rsa.PrivateKey",
				"test_2_pri": "*rsa.PrivateKey",
				"test_2_pub": "*rsa.PublicKey",
			},
		},
		{
			name: "simple env file",
			env:  map[string]string{"JWT_RSA_FILE": dirCWD + "/../../testdata/rskeys/test_1_pri.pem"},
			expect: map[string]string{
				"0": "*rsa.PrivateKey",
			},
		},
		{
			name: "simple env key",
			env:  map[string]string{"JWT_RSA_KEY": testPriKey},
			expect: map[string]string{
				"0": "*rsa.PrivateKey",
			},
		},
		{
			name: "simple env files",
			env:  map[string]string{"JWT_RSA_FILE_APPLE": dirCWD + "/../../testdata/rskeys/test_1_pri.pem"},
			expect: map[string]string{
				"apple": "*rsa.PrivateKey",
			},
		},
		{
			name: "simple env keys",
			env:  map[string]string{"JWT_RSA_KEY_PEAR": testPriKey},
			expect: map[string]string{
				"pear": "*rsa.PrivateKey",
			},
		},
		{
			name:   "config over env key",
			config: `{"token_rsa_keys": {"pear": "` + strings.Replace(testPriKey, "\n", "\\n", -1) + `"}}`,
			env:    map[string]string{"JWT_RSA_KEY_PEAR": testPubKey},
			expect: map[string]string{
				"pear": "*rsa.PrivateKey",
			},
		},
		{
			name: "config key over config file",
			config: `{
                "token_rsa_files": {"pear": "./../../testdata/rskeys/test_2_pri.pem"},
                "token_rsa_keys": {"pear": "` + strings.Replace(testPriKey, "\n", "\\n", -1) + `"}
            }`,
			shouldErr: true,
			err:       errors.ErrFoundDuplicateKeyID.WithArgs("pear", "rsa", "config"),
		},
		{
			name: "config key mix config file",
			config: `{
                "token_rsa_files": {"banana": "` + dirCWD + `/../../testdata/rskeys/test_2_pri.pem"},
                "token_rsa_keys": {"pear": "` + strings.Replace(testPriKey, "\n", "\\n", -1) + `"}
            }`,
			expect: map[string]string{
				"banana": "*rsa.PrivateKey",
				"pear":   "*rsa.PrivateKey",
			},
		},
		{
			name: "config keys explict over implied",
			config: `{
                 "token_rsa_key": "` + strings.Replace(testPubKey, "\n", "\\n", -1) + `",
                 "token_rsa_keys": {"0": "` + strings.Replace(testPriKey, "\n", "\\n", -1) + `"}
            }`,
			shouldErr: true,
			err:       errors.ErrFoundDuplicateKeyID.WithArgs("0", "rsa", "config"),
		},
		{
			name:   "ecdsa simple config dir",
			config: `{"token_ecdsa_dir": "./../../testdata/ecdsakeys"}`,
			expect: map[string]string{
				"private":    "*ecdsa.PrivateKey",
				"test_1_pri": "*ecdsa.PrivateKey",
				"test_2_pri": "*ecdsa.PrivateKey",
				"test_2_pub": "*ecdsa.PublicKey",
				"test_3_pri": "*ecdsa.PrivateKey",
				"test_4_pri": "*ecdsa.PrivateKey",
			},
		},
		{
			name:   "ecdsa simple config file",
			config: `{"token_ecdsa_file": "` + dirCWD + `/../../testdata/ecdsakeys/test_1_pri.pem"}`,
			expect: map[string]string{
				"0": "*ecdsa.PrivateKey",
			},
		},
		{
			name:   "ecdsa simple config key",
			config: `{"token_ecdsa_key": "` + strings.Replace(testEcdsaPriKey, "\n", "\\n", -1) + `"}`,
			expect: map[string]string{
				"0": "*ecdsa.PrivateKey",
			},
		},
		{
			name:   "ecdsa simple config files",
			config: `{"token_ecdsa_files": {"apple": "./../../testdata/ecdsakeys/test_1_pri.pem"}}`,
			expect: map[string]string{
				"apple": "*ecdsa.PrivateKey",
			},
		},
		{
			name:   "ecdsa simple config keys",
			config: `{"token_ecdsa_keys": {"pear": "` + strings.Replace(testEcdsaPriKey, "\n", "\\n", -1) + `"}}`,
			expect: map[string]string{
				"pear": "*ecdsa.PrivateKey",
			},
		},
		{
			name: "ecdsa simple env dir",
			env:  map[string]string{"JWT_ECDSA_DIR": "./../../testdata/ecdsakeys"},
			expect: map[string]string{
				"private":    "*ecdsa.PrivateKey",
				"test_1_pri": "*ecdsa.PrivateKey",
				"test_2_pri": "*ecdsa.PrivateKey",
				"test_2_pub": "*ecdsa.PublicKey",
				"test_3_pri": "*ecdsa.PrivateKey",
				"test_4_pri": "*ecdsa.PrivateKey",
			},
		},
		{
			name: "ecdsa simple env file",
			env:  map[string]string{"JWT_ECDSA_FILE": dirCWD + "/../../testdata/ecdsakeys/test_1_pri.pem"},
			expect: map[string]string{
				"0": "*ecdsa.PrivateKey",
			},
		},
		{
			name: "ecdsa simple env key",
			env:  map[string]string{"JWT_ECDSA_KEY": testEcdsaPriKey},
			expect: map[string]string{
				"0": "*ecdsa.PrivateKey",
			},
		},
		{
			name: "ecdsa simple env files",
			env:  map[string]string{"JWT_ECDSA_FILE_APPLE": dirCWD + "/../../testdata/ecdsakeys/test_1_pri.pem"},
			expect: map[string]string{
				"apple": "*ecdsa.PrivateKey",
			},
		},
		{
			name: "ecdsa simple env keys",
			env:  map[string]string{"JWT_ECDSA_KEY_PEAR": testEcdsaPriKey},
			expect: map[string]string{
				"pear": "*ecdsa.PrivateKey",
			},
		},
		{
			name:   "ecdsa config over env key",
			config: `{"token_ecdsa_keys": {"pear": "` + strings.Replace(testEcdsaPriKey, "\n", "\\n", -1) + `"}}`,
			env:    map[string]string{"JWT_ECDSA_KEY_PEAR": testEcdsaPubKey},
			expect: map[string]string{
				"pear": "*ecdsa.PrivateKey",
			},
		},
		{
			name: "ecdsa config key over config file",
			config: `{
                "token_ecdsa_files": {"pear": "./../../testdata/ecdsakeys/test_2_pub.pem"},
                "token_ecdsa_keys": {"pear": "` + strings.Replace(testEcdsaPriKey, "\n", "\\n", -1) + `"}
            }`,
			shouldErr: true,
			err:       errors.ErrFoundDuplicateKeyID.WithArgs("pear", "ecdsa", "config"),
		},
		{
			name: "ecdsa config key mix config file",
			config: `{
                "token_ecdsa_files": {"banana": "` + dirCWD + `/../../testdata/ecdsakeys/test_2_pub.pem"},
                "token_ecdsa_keys": {"pear": "` + strings.Replace(testEcdsaPriKey, "\n", "\\n", -1) + `"}
            }`,
			expect: map[string]string{
				"banana": "*ecdsa.PublicKey",
				"pear":   "*ecdsa.PrivateKey",
			},
		},
		{
			name: "ecdsa config keys explicit over implied",
			config: `{
                "token_ecdsa_key": "` + strings.Replace(testEcdsaPubKey, "\n", "\\n", -1) + `",
                "token_ecdsa_keys": {"0": "` + strings.Replace(testEcdsaPriKey, "\n", "\\n", -1) + `"}
            }`,
			shouldErr: true,
			err:       errors.ErrFoundDuplicateKeyID.WithArgs("0", "ecdsa", "config"),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var km *KeyManager
			var err error

			for k, v := range tc.env {
				os.Setenv(k, v)
				defer os.Unsetenv(k)
			}

			if tc.config != "" {
				tokenConfig := NewTokenConfig()
				err = json.Unmarshal([]byte(tc.config), tokenConfig)
				// if tests.EvalErr(t, err, nil, tc.shouldErr, tc.err) {
				//	return
				// }
				km, err = NewKeyManager(tokenConfig)
			} else {
				km, err = NewKeyManager(nil)
			}
			if tests.EvalErr(t, err, km, tc.shouldErr, tc.err) {
				return
			}

			if tc.tokenName != "" {
				tests.EvalObjects(t, "configured token name", tc.tokenName, km.tokenConfig.Name)
			} else {
				tests.EvalObjects(t, "default token name", defaultTokenName, km.tokenConfig.Name)
			}

			if tc.tokenLifetime > 0 {
				tests.EvalObjects(t, "configured token lifetime", tc.tokenLifetime, km.tokenConfig.Lifetime)
			} else {
				tests.EvalObjects(t, "default token lifetime", defaultTokenLifetime, km.tokenConfig.Lifetime)
			}

			if tc.keyOrigin != "" {
				tests.EvalObjects(t, "key origin", tc.keyOrigin, km.GetOrigin())
			} else {
				if tc.config != "" {
					tests.EvalObjects(t, "key origin", "config", km.GetOrigin())
				} else {
					tests.EvalObjects(t, "key origin", "env", km.GetOrigin())
				}
			}

			var mm map[string]string
			_, keys := km.GetKeys()
			if keys != nil {
				mm = make(map[string]string)
			}
			for kid, key := range keys {
				mm[kid] = fmt.Sprintf("%T", key.Secret)
			}
			tests.EvalObjects(t, "output", tc.expect, mm)
		})
	}
}

// testPriKey is RSA private key. See `testdata/rskeys/test_2_pri.pem`.
var testPriKey = `-----BEGIN RSA PRIVATE KEY-----
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

// testPubKey is RSA public key. See `testdata/rskeys/test_2_pri.pem`.
var testPubKey = `-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgEMFBKcGW7iRRlJdIuF0/5YmB3AC
sCd6hWCFk4FGAj7G+sd4m9GGU/9ae9x00yvkY2Pit03B5kxHQfVAqKG6PnTzRg5c
bwjPjnhFiPeLfGWMKIIEkhTacuIu8Tr+hmMchxCUYl9twakFl3bOVsHqmMcByJ44
FII66Kl4z6k4ERKZAgMBAAE=
-----END PUBLIC KEY-----`

// testEcdsaPriKey is ECDSA private key. See `testdata/ecdsakeys/test_2_pri.pem`.
var testEcdsaPriKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBQE/25Y74Lk7/BEN18fWctVXpI5rHvTP297o/Kjz+FdoAoGCCqGSM49
AwEHoUQDQgAEFNRTaMQpy2ecKe87mtHxAIr9q1fDNRBp93O6c7sDqr1XQtOj0GzI
HoLWsGps+E3kU6/xciYXGjboc98OJWweLQ==
-----END EC PRIVATE KEY-----`

// testEcdsaPubKey is ECDSA public key. See `testdata/ecdsakeys/test_2_pub.pem`.
var testEcdsaPubKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFNRTaMQpy2ecKe87mtHxAIr9q1fD
NRBp93O6c7sDqr1XQtOj0GzIHoLWsGps+E3kU6/xciYXGjboc98OJWweLQ==
-----END PUBLIC KEY-----`
