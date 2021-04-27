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
	"os"
	"strings"
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

func TestGetKeysFromConfig(t *testing.T) {
	var testcases = []struct {
		name   string
		config string
		env    map[string]string
		want   map[string]interface{}
		log    bool
		// keyPair indicates which keys are being used for sign/verification.
		keyPair   []int
		shouldErr bool
		err       error
	}{
		{
			name: "default shared key in default context",
			config: `
                crypto key token name "foobar token"
                crypto key sign-verify foobar
            `,
			keyPair: []int{0, 0},
			want: map[string]interface{}{
				"config_count": 1,
				"key_count":    1,
				"keys": []string{
					"0: sign   0: []uint8",
					"0: verify 0: []uint8",
				},
			},
		},
		{
			name: "shared secret embedded in environment variable",
			config: `
                crypto key cb315f43c868 sign-verify from env JWT_SHARED_SECRET
            `,
			env: map[string]string{
				"JWT_TOKEN_LIFETIME": "3600",
				"JWT_SHARED_SECRET":  "foobar",
			},
			keyPair: []int{0, 0},
			want: map[string]interface{}{
				"config_count": 1,
				"key_count":    1,
				"keys": []string{
					"0: sign   cb315f43c868: []uint8",
					"0: verify cb315f43c868: []uint8",
				},
			},
		},
		{
			name: "rsa key embedded in environment variable",
			config: `
                crypto key cb315f43c868 sign-verify from env JWT_SHARED_SECRET
            `,
			env: map[string]string{
				"JWT_TOKEN_LIFETIME": "3600",
				"JWT_SHARED_SECRET":  "file:./../../testdata/rskeys/test_2_pri.pem",
			},
			keyPair: []int{0, 0},
			want: map[string]interface{}{
				"config_count": 1,
				"key_count":    1,
				"keys": []string{
					"0: sign   cb315f43c868: *rsa.PrivateKey",
					"0: verify cb315f43c868: *rsa.PublicKey",
				},
			},
		},
		{
			name: "bad rsa key embedded in environment variable",
			// log:  true,
			config: `
                crypto key cb315f43c868 sign-verify from env JWT_SHARED_SECRET
            `,
			env: map[string]string{
				"JWT_SHARED_SECRET": "-----BEGIN PRIVATE",
			},
			shouldErr: true,
			err:       errors.ErrNotPEMEncodedKey,
		},
		{
			name: "bad rsa key embedded in environment variable",
			// log:  true,
			config: `
                crypto key cb315f43c868 sign-verify from env JWT_SHARED_SECRET
            `,
			env: map[string]string{
				"JWT_SHARED_SECRET": "-----BEGIN PRIVATE ---END PRIVATE",
			},
			shouldErr: true,
			err:       errors.ErrNotPEMEncodedKey,
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
				"keys": []string{
					"0: sign   k9738a405e99: *rsa.PrivateKey",
					"1: verify k9738a405e99: *rsa.PublicKey",
				},
			},
		},
		{
			name: "load private and public rsa and ecdsa keys from file path",
			config: `
                crypto key k9738a405e99 sign-verify from file ./../../testdata/misckeys/rsa_test_2_pri.pem
                crypto key k9738a405e11 sign-verify from file ./../../testdata/misckeys/ecdsa_test_2_pri.pem
            `,
			keyPair: []int{0, 0},
			want: map[string]interface{}{
				"config_count": 2,
				"key_count":    2,
				"keys": []string{
					"0: sign   k9738a405e99: *rsa.PrivateKey",
					"0: verify k9738a405e99: *rsa.PublicKey",
					"1: sign   k9738a405e11: *ecdsa.PrivateKey",
					"1: verify k9738a405e11: *ecdsa.PublicKey",
				},
			},
		},
		{
			name: "load private rsa key from file path for both sign and verify",
			config: `
                crypto key k9738a405e99 sign-verify from file ./../../testdata/rskeys/test_1_pri.pem
            `,
			keyPair: []int{0, 0},
			want: map[string]interface{}{
				"config_count": 1,
				"key_count":    1,
				"keys": []string{
					"0: sign   k9738a405e99: *rsa.PrivateKey",
					"0: verify k9738a405e99: *rsa.PublicKey",
				},
			},
		},
		{
			name: "load private and public ecdsa keys from file path",
			config: `
                crypto key k9738a405e99 sign from file ./../../testdata/ecdsakeys/test_2_pri.pem
                crypto key k9738a405e99 verify from file ./../../testdata/ecdsakeys/test_2_pub.pem
            `,
			keyPair: []int{0, 1},
			want: map[string]interface{}{
				"config_count": 2,
				"key_count":    2,
				"keys": []string{
					"0: sign   k9738a405e99: *ecdsa.PrivateKey",
					"1: verify k9738a405e99: *ecdsa.PublicKey",
				},
			},
		},
		{
			name: "load private ecdsa key from file path for both sign and verify",
			config: `
                crypto key k9738a405e99 sign-verify from file ./../../testdata/ecdsakeys/test_1_pri.pem
            `,
			keyPair: []int{0, 0},
			want: map[string]interface{}{
				"config_count": 1,
				"key_count":    1,
				"keys": []string{
					"0: sign   k9738a405e99: *ecdsa.PrivateKey",
					"0: verify k9738a405e99: *ecdsa.PublicKey",
				},
			},
		},
		{
			name: "load private ecdsa key from environment variable with file path for both sign and verify",
			config: `
                crypto key cb315f43c868 sign-verify from env JWT_SECRET_FILE as file
            `,
			env: map[string]string{
				"JWT_SECRET_FILE": "./../../testdata/rskeys/test_1_pri.pem",
			},
			keyPair: []int{0, 0},
			want: map[string]interface{}{
				"config_count": 1,
				"key_count":    1,
				"keys": []string{
					"0: sign   cb315f43c868: *rsa.PrivateKey",
					"0: verify cb315f43c868: *rsa.PublicKey",
				},
			},
		},
		{
			name: "load keys from rsa directory path",
			config: `
                crypto key k9738a405e99 verify from directory ./../../testdata/rskeys
            `,
			want: map[string]interface{}{
				"config_count": 1,
				"key_count":    4,
				"keys": []string{
					"0: sign   test_1_pri: *rsa.PrivateKey",
					"0: verify test_1_pri: *rsa.PublicKey",
					"1: sign   test_2_pri: *rsa.PrivateKey",
					"1: verify test_2_pri: *rsa.PublicKey",
					"2: verify test_2_pub: *rsa.PublicKey",
					"3: sign   private: *rsa.PrivateKey",
					"3: verify private: *rsa.PublicKey",
				},
			},
		},

		{
			name: "load keys from rsa directory path via env vars",
			config: `
                crypto key cb315f43c868 sign-verify from env JWT_SECRET_DIR as directory
            `,
			env: map[string]string{
				"JWT_SECRET_DIR": "./../../testdata/rskeys",
			},
			want: map[string]interface{}{
				"config_count": 1,
				"key_count":    4,
				"keys": []string{
					"0: sign   test_1_pri: *rsa.PrivateKey",
					"0: verify test_1_pri: *rsa.PublicKey",
					"1: sign   test_2_pri: *rsa.PrivateKey",
					"1: verify test_2_pri: *rsa.PublicKey",
					"2: verify test_2_pub: *rsa.PublicKey",
					"3: sign   private: *rsa.PrivateKey",
					"3: verify private: *rsa.PublicKey",
				},
			},
		},
		{
			name: "load keys from rsa directory path",
			config: `
                crypto key k9738a405e99 verify from directory ./../../testdata/nokeys/docs
            `,
			shouldErr: true,
			err:       errors.ErrWalkDir.WithArgs("no crypto keys found"),
		},
		{
			name: "load keys from rsa directory path",
			config: `
                crypto key k9738a405e99 verify from directory ./../../testdata/nokeys/bad
            `,
			shouldErr: true,
			err: errors.ErrWalkDir.WithArgs(
				errors.ErrCryptoKeyConfigReadFile.WithArgs(
					"../../testdata/nokeys/bad/bad_begin_only.key",
					errors.ErrNotPEMEncodedKey,
				),
			),
		},
		{
			name: "load keys from ecdsa directory path",
			config: `
                crypto key k9738a405e99 verify from directory ./../../testdata/ecdsakeys
            `,
			want: map[string]interface{}{
				"config_count": 1,
				"key_count":    6,
				"keys": []string{
					"0: sign   test_1_pri: *ecdsa.PrivateKey",
					"0: verify test_1_pri: *ecdsa.PublicKey",
					"1: sign   test_2_pri: *ecdsa.PrivateKey",
					"1: verify test_2_pri: *ecdsa.PublicKey",
					"2: verify test_2_pub: *ecdsa.PublicKey",
					"3: sign   test_3_pri: *ecdsa.PrivateKey",
					"3: verify test_3_pri: *ecdsa.PublicKey",
					"4: sign   test_4_pri: *ecdsa.PrivateKey",
					"4: verify test_4_pri: *ecdsa.PublicKey",
					"5: sign   private: *ecdsa.PrivateKey",
					"5: verify private: *ecdsa.PublicKey",
				},
			},
		},
		{
			name: "private rsa key wrapped in ec header",
			config: `
                crypto key k9738a405e99 sign-verify from file ./../../testdata/malformed/ec_header_rsa_pri.pem
            `,
			shouldErr: true,
			err: errors.ErrCryptoKeyConfigReadFile.WithArgs(
				"./../../testdata/malformed/ec_header_rsa_pri.pem",
				`x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)`,
			),
		},
		{
			name: "private ec key wrapped in rsa header",
			config: `
                crypto key k9738a405e99 sign-verify from file ./../../testdata/malformed/rsa_header_ec_pri.pem
            `,
			shouldErr: true,
			err: errors.ErrCryptoKeyConfigReadFile.WithArgs(
				"./../../testdata/malformed/rsa_header_ec_pri.pem",
				`x509: failed to parse private key (use ParseECPrivateKey instead for this key format)`,
			),
		},
		{
			name: "public key passed as private",
			config: `
                crypto key k9738a405e99 sign-verify from file ./../../testdata/malformed/rsa_pub_as_pri.pem
            `,
			shouldErr: true,

			err: errors.ErrCryptoKeyConfigReadFile.WithArgs(
				"./../../testdata/malformed/rsa_pub_as_pri.pem",
				`asn1: structure error: tags don't match (2 vs {class:0 tag:16 length:19 isCompound:true}) `+
					`{optional:false explicit:false application:false private:false defaultValue:<nil> `+
					`tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} int @2`,
			),
		},
		{
			name: "private key passed as public",
			config: `
                crypto key k9738a405e99 sign-verify from file ./../../testdata/malformed/rsa_pri_as_pub.pem
            `,
			shouldErr: true,
			err: errors.ErrCryptoKeyConfigReadFile.WithArgs(
				"./../../testdata/malformed/rsa_pri_as_pub.pem",
				`asn1: structure error: tags don't match (16 vs {class:0 tag:2 length:1 isCompound:false}) `+
					`{optional:false explicit:false application:false private:false defaultValue:<nil> `+
					`tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} AlgorithmIdentifier @2`,
			),
		},
		{
			name: "cert passed as private key",
			config: `
                crypto key k9738a405e99 sign-verify from file ./../../testdata/malformed/cert.pem
            `,
			shouldErr: true,
			err: errors.ErrCryptoKeyConfigReadFile.WithArgs(
				"./../../testdata/malformed/cert.pem",
				errors.ErrNotPEMEncodedKey,
			),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("config: %s", tc.config))
			for k, v := range tc.env {
				if strings.HasPrefix(v, "file:") {
					b, err := extractBytesFromFile(strings.TrimPrefix(v, "file:"))
					if err != nil {
						t.Fatal(err)
					}
					v = string(b)
				}
				msgs = append(msgs, fmt.Sprintf("env: %s = %s", k, v))
				os.Setenv(k, v)
				defer os.Unsetenv(k)
			}

			configs, err := ParseCryptoKeyConfigs(tc.config)
			if err != nil {
				t.Fatal(err)
			}

			if tc.log {
				for _, c := range configs {
					t.Logf("%s", c.ToString())
				}
			}

			keys, err := GetKeysFromConfigs(configs)
			if tests.EvalErrWithLog(t, err, "keys", tc.shouldErr, tc.err, msgs) {
				return
			}

			got := make(map[string]interface{})
			got["config_count"] = len(configs)
			got["key_count"] = len(keys)

			var km []string
			for i, k := range keys {
				if k.Sign.Token.Capable {
					km = append(km, fmt.Sprintf("%d: sign   %s: %T", i, k.Sign.Token.ID, k.Sign.Secret))
				}
				if k.Verify.Token.Capable {
					km = append(km, fmt.Sprintf("%d: verify %s: %T", i, k.Verify.Token.ID, k.Verify.Secret))
				}
			}
			got["keys"] = km

			if tc.log {
				t.Logf("crypto configs:\n%s", cmp.Diff(nil, configs))
				for i, key := range keys {
					t.Logf("crypto key %d:\n%s", i, cmp.Diff(nil, key))
				}
			}

			if diff := cmp.Diff(tc.want, got, cmp.AllowUnexported(CryptoKeyConfig{})); diff != "" {
				tests.WriteLog(t, msgs)
				t.Fatalf("output mismatch (-want +got):\n%s", diff)
			}

			if len(tc.keyPair) != 2 {
				return
			}

			var privKey, pubKey *CryptoKey
			for i, j := range tc.keyPair {
				if j >= len(keys) {
					break
				}
				if i == 0 {
					privKey = keys[j]
					continue
				}
				pubKey = keys[j]
			}

			ks := NewCryptoKeyStore()
			if err := ks.AddKeys([]*CryptoKey{privKey, pubKey}); err != nil {
				t.Fatal(err)
			}
			usr := newTestUser()
			if tc.log {
				t.Logf("%v", usr)
			}

			if err := ks.SignToken(privKey.Sign.Token.Name, privKey.Sign.Token.DefaultMethod, usr); err != nil {
				t.Fatal(err)
			}

			if tc.log {
				t.Logf("token %v: %s", privKey.Sign.Token.Name, usr.Token)
			}

			tokenUser, err := ks.ParseToken(pubKey.Verify.Token.Name, usr.Token)
			if err != nil {
				t.Fatal(err)
			}
			if tc.log {
				t.Logf("user:\n%s", cmp.Diff(nil, tokenUser))
			}
		})
	}
}

func TestGetKeysFromCryptoKeyConfigs(t *testing.T) {
	var testcases = []struct {
		name      string
		config    *CryptoKeyConfig
		shouldErr bool
		err       error
	}{
		{
			name: "bad config file path",
			config: &CryptoKeyConfig{
				Source:   "config",
				FilePath: "foo",
			},
			shouldErr: true,
			err:       fmt.Errorf(`kms: file "foo" is not supported due to extension type`),
		},
		{
			name: "bad config dir path",
			config: &CryptoKeyConfig{
				Source:  "config",
				DirPath: "foo",
			},
			shouldErr: true,
			err:       fmt.Errorf(`walking directory: lstat foo: no such file or directory`),
		},
		{
			name: "bad config without file dir path",
			config: &CryptoKeyConfig{
				Source: "config",
			},
			shouldErr: true,
			err:       fmt.Errorf(`unsupported config`),
		},
		{
			name: "bad env file path",
			config: &CryptoKeyConfig{
				Source:      "env",
				EnvVarType:  "file",
				EnvVarValue: "foo",
			},
			shouldErr: true,
			err:       fmt.Errorf(`kms: file "foo" is not supported due to extension type`),
		},
		{
			name: "bad env dir path",
			config: &CryptoKeyConfig{
				Source:      "env",
				EnvVarType:  "directory",
				EnvVarValue: "foo",
			},
			shouldErr: true,
			err:       fmt.Errorf(`walking directory: lstat foo: no such file or directory`),
		},
		{
			name: "bad env without file dir path",
			config: &CryptoKeyConfig{
				Source:      "env",
				EnvVarType:  "foo",
				EnvVarValue: "foo",
			},
			shouldErr: true,
			err:       fmt.Errorf(`unsupported env config type foo`),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("config: %v", tc.config))
			_, err := GetKeysFromConfigs([]*CryptoKeyConfig{tc.config})
			if tests.EvalErrWithLog(t, err, nil, tc.shouldErr, tc.err, msgs) {
				return
			}
		})
	}
}
