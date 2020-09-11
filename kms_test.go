package jwt

import (
	"crypto/rsa"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestRSASource(t *testing.T) {
	logger, _ := zap.NewProduction()

	dirDot := "."             // test that we can use a "./" path
	dirCWD, err := os.Getwd() // that that we can use a full path
	if err != nil {
		t.Fatal(err)
	}

	var tests = []struct {
		name       string
		env        map[string]string
		configJSON string
		expect     map[string]string
	}{
		{
			name:   "empty",
			expect: nil,
		},
		{
			name:       "simple config dir",
			configJSON: `{"token_rsa_dir": "` + dirDot + `/testdata/rskeys"}`,
			expect: map[string]string{
				"username_private": "*rsa.PrivateKey",
				"test_1":           "*rsa.PrivateKey",
				"test_2":           "*rsa.PublicKey",
			},
		},
		{
			name:       "simple config file",
			configJSON: `{"token_rsa_file": "` + dirCWD + `/testdata/rskeys/test_1.key"}`,
			expect: map[string]string{
				"0": "*rsa.PrivateKey",
			},
		},
		{
			name:       "simple config key",
			configJSON: `{"token_rsa_key": "` + strings.Replace(testPriKey, "\n", "\\n", -1) + `"}`,
			expect: map[string]string{
				"0": "*rsa.PrivateKey",
			},
		},
		{
			name:       "simple config files",
			configJSON: `{"token_rsa_files": {"apple": "` + dirDot + `/testdata/rskeys/test_1.key"}}`,
			expect: map[string]string{
				"apple": "*rsa.PrivateKey",
			},
		},
		{
			name:       "simple config keys",
			configJSON: `{"token_rsa_keys": {"pear": "` + strings.Replace(testPriKey, "\n", "\\n", -1) + `"}}`,
			expect: map[string]string{
				"pear": "*rsa.PrivateKey",
			},
		},
		{
			name: "simple env dir",
			env:  map[string]string{"JWT_RSA_DIR": dirDot + "/testdata/rskeys"},
			expect: map[string]string{
				"username_private": "*rsa.PrivateKey",
				"test_1":           "*rsa.PrivateKey",
				"test_2":           "*rsa.PublicKey",
			},
		},
		{
			name: "simple env file",
			env:  map[string]string{"JWT_RSA_FILE": dirCWD + "/testdata/rskeys/test_1.key"},
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
			env:  map[string]string{"JWT_RSA_FILE_APPLE": dirCWD + "/testdata/rskeys/test_1.key"},
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
			name:       "config env keys mix",
			configJSON: `{"token_rsa_keys": {"pear": "` + strings.Replace(testPriKey, "\n", "\\n", -1) + `"}}`,
			env:        map[string]string{"JWT_RSA_KEY_GRAPE": testPubKey},
			expect: map[string]string{
				"pear":  "*rsa.PrivateKey",
				"grape": "*rsa.PublicKey",
			},
		},
		{
			name:       "config over env key",
			configJSON: `{"token_rsa_keys": {"pear": "` + strings.Replace(testPriKey, "\n", "\\n", -1) + `"}}`,
			env:        map[string]string{"JWT_RSA_KEY_PEAR": testPubKey},
			expect: map[string]string{
				"pear": "*rsa.PrivateKey",
			},
		},
		{
			name: "config key over config file",
			configJSON: `{
				"token_rsa_files": {"pear": "` + dirDot + `/testdata/rskeys/test_2.key"},
				"token_rsa_keys": {"pear": "` + strings.Replace(testPriKey, "\n", "\\n", -1) + `"}
			}`,
			expect: map[string]string{
				"pear": "*rsa.PrivateKey",
			},
		},
		{
			name: "config key mix config file",
			configJSON: `{
				"token_rsa_files": {"banana": "` + dirCWD + `/testdata/rskeys/test_2.key"},
				"token_rsa_keys": {"pear": "` + strings.Replace(testPriKey, "\n", "\\n", -1) + `"}
			}`,
			expect: map[string]string{
				"banana": "*rsa.PublicKey",
				"pear":   "*rsa.PrivateKey",
			},
		},
		{
			name: "config keys explict over implied",
			configJSON: `{
				"token_rsa_key": "` + strings.Replace(testPubKey, "\n", "\\n", -1) + `",
				"token_rsa_keys": {"0": "` + strings.Replace(testPriKey, "\n", "\\n", -1) + `"}
			}`,
			expect: map[string]string{
				"0": "*rsa.PrivateKey",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var m = &AuthProvider{}
			m.logger = logger

			if test.configJSON != "" {
				err := json.Unmarshal([]byte(test.configJSON), m)
				if err != nil {
					t.Error(err)
					return
				}
			}

			for k, v := range test.env {
				os.Setenv(k, v)
			}

			for _, c := range m.TrustedTokens {
				if err := loadEncryptionKeys(c); err != nil {
					t.Error(err)
					return
				}

				for k := range test.env {
					os.Unsetenv(k)
				}

				var mm map[string]string
				if c.tokenKeys != nil {
					mm = make(map[string]string)
				}

				for k, v := range c.tokenKeys {
					switch v.(type) {
					case *rsa.PrivateKey:
						mm[k] = "*rsa.PrivateKey"
					case *rsa.PublicKey:
						mm[k] = "*rsa.PublicKey"
					}
				}

				if !reflect.DeepEqual(mm, test.expect) {
					t.Errorf("got: %#v\nexpected: %#v", mm, test.expect)
				}
			}
		})
	}
}

// testPriKey is the same as "test-priv-2.key"
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

// testPubKey is the public key
var testPubKey = `-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgEMFBKcGW7iRRlJdIuF0/5YmB3AC
sCd6hWCFk4FGAj7G+sd4m9GGU/9ae9x00yvkY2Pit03B5kxHQfVAqKG6PnTzRg5c
bwjPjnhFiPeLfGWMKIIEkhTacuIu8Tr+hmMchxCUYl9twakFl3bOVsHqmMcByJ44
FII66Kl4z6k4ERKZAgMBAAE=
-----END PUBLIC KEY-----`
