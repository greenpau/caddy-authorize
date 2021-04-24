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
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"go.uber.org/zap"
	"sort"
	"strconv"
	"strings"
)

const (
	defaultKeyID             = "0"
	defaultTokenName         = "access_token"
	defaultTokenLifetime int = 900
)

var (
	reservedKeyConfigKeywords = map[string]bool{
		"crypto":   true,
		"key":      true,
		"sign":     true,
		"verify":   true,
		"and":      true,
		"token":    true,
		"lifetime": true,
		"from":     true,
		"env":      true,
		"as":       true,
	}
)

const (
	// EnvTokenRSADir the env variable used to indicate a directory
	EnvTokenRSADir = "JWT_RSA_DIR"
	// EnvTokenRSAFile then env variable (or prefix) used to indicate a file containing a RS key
	EnvTokenRSAFile = "JWT_RSA_FILE"
	// EnvTokenRSAKey the env variable (or prefix) used to indicte a RS key
	EnvTokenRSAKey = "JWT_RSA_KEY"
	// EnvTokenECDSADir the env variable used to indicate a directory containing ECDSA keys.
	EnvTokenECDSADir = "JWT_ECDSA_DIR"
	// EnvTokenECDSAFile then env variable (or prefix) used to indicate a file containing ECDSA key.
	EnvTokenECDSAFile = "JWT_ECDSA_FILE"
	// EnvTokenECDSAKey the env variable (or prefix) used to indicate ECDSA key.
	EnvTokenECDSAKey = "JWT_ECDSA_KEY"
	// EnvTokenSecret the env variable used to indicate shared secret key.
	EnvTokenSecret = "JWT_TOKEN_SECRET"
	// EnvTokenLifetime the env variable used to set default token lifetime.
	EnvTokenLifetime = "JWT_TOKEN_LIFETIME"
	// EnvTokenName the env variable used to set default token name.
	EnvTokenName = "JWT_TOKEN_NAME"
)

// CryptoKeyConfig is common token-related configuration settings.
type CryptoKeyConfig struct {
	Name       string            `json:"token_name,omitempty" xml:"token_name" yaml:"token_name"`
	SignMethod string            `json:"token_sign_method,omitempty" xml:"token_sign_method,omitempty" yaml:"token_sign_method,omitempty"`
	Lifetime   int               `json:"token_lifetime,omitempty" xml:"token_lifetime" yaml:"token_lifetime"`
	EvalExpr   []string          `json:"token_eval_expr,omitempty" xml:"token_eval_expr" yaml:"token_eval_expr"`
	RSADir     string            `json:"token_rsa_dir,omitempty" xml:"token_rsa_dir" yaml:"token_rsa_dir"`
	RSAFiles   map[string]string `json:"token_rsa_files,omitempty" xml:"token_rsa_files" yaml:"token_rsa_files"`
	RSAKeys    map[string]string `json:"token_rsa_keys,omitempty" xml:"token_rsa_keys" yaml:"token_rsa_keys"`
	RSAFile    string            `json:"token_rsa_file,omitempty" xml:"token_rsa_file" yaml:"token_rsa_file"`
	RSAKey     string            `json:"token_rsa_key,omitempty" xml:"token_rsa_key" yaml:"token_rsa_key"`
	ECDSADir   string            `json:"token_ecdsa_dir,omitempty" xml:"token_ecdsa_dir" yaml:"token_ecdsa_dir"`
	ECDSAFiles map[string]string `json:"token_ecdsa_files,omitempty" xml:"token_ecdsa_files" yaml:"token_ecdsa_files"`
	ECDSAKeys  map[string]string `json:"token_ecdsa_keys,omitempty" xml:"token_ecdsa_keys" yaml:"token_ecdsa_keys"`
	ECDSAFile  string            `json:"token_ecdsa_file,omitempty" xml:"token_ecdsa_file" yaml:"token_ecdsa_file"`
	ECDSAKey   string            `json:"token_ecdsa_key,omitempty" xml:"token_ecdsa_key" yaml:"token_ecdsa_key"`

	// Seq is the order in which a key would be processed.
	Seq int
	// ID is the key ID, aka kid.
	ID string
	// Usage is the intended key usage. The values are: sign, verify, both,
	// or auto.
	Usage string
	// TokenName is the token name associated with the key.
	TokenName string
	// Source is either config or env.
	Source string
	// Algorithm is either hmac, rsa, or ecdsa.
	Algorithm string
	// EnvVarName is the name of environment variables holding either the value of
	// a key or the path a directory or file containing a key.
	EnvVarName string
	// EnvVarType indicates how to interpret the value found in the EnvVarName. If
	// it is blank, then the assumption is the environment variable value
	// contains either public or private key.
	EnvVarType string
	// FilePath is the path of a file containing either private or public key.
	FilePath string
	// DirPath is the path to a directory containing crypto keys.
	DirPath string
	// TokenLifetime is the expected token grant lifetime in seconds.
	TokenLifetime int
	// Secret is the shared key used with HMAC algorithm.
	Secret string `json:"token_secret,omitempty" xml:"token_secret" yaml:"token_secret"`
	// PreferredSignMethod is the preferred method to sign tokens, e.g.
	// all HMAC keys could use HS256, HS384, and HS512 methods. By default,
	// the preferred method is HS512. However, one may prefer using HS256.
	PreferredSignMethod string `json:"token_sign_method,omitempty" xml:"token_sign_method,omitempty" yaml:"token_sign_method,omitempty"`
	// AutoGenerated is enabled when the key needs to be auto-generated. The
	// key is exposed by sharing via shared package.
	AutoGenerated bool
	validated     bool
}

// NewCryptoKeyConfig returns an instance of CryptoKeyConfig.
func NewCryptoKeyConfig(params ...interface{}) (*CryptoKeyConfig, error) {
	var argCount int
	var args []string

	for i, arg := range params {
		argCount++
		switch i {
		case 0:
			if arg == nil {
				return nil, errors.ErrCryptoKeyConfigNewArgTypeInvalid.WithArgs([]interface{}{})
			}
			switch v := arg.(type) {
			case string:
				if isMethodSupported(v) {
					args = append(args, v)
					break
				}
				return newCryptoKeyConfigFromJSON([]byte(v))
			case []uint8:
				return newCryptoKeyConfigFromJSON(v)
				//default:
				//	return nil, errors.ErrCryptoKeyConfigNewArgTypeInvalid.WithArgs(v)
			}
		default:
			switch v := arg.(type) {
			case string:
				args = append(args, v)
			}
		}
	}
	if argCount == 0 {
		return &CryptoKeyConfig{}, nil
	}

	if len(args) > 0 {
		if isMethodSupported(args[0]) {
			return newCryptoKeyConfigFromSecret(args)
		}
	}

	return nil, errors.ErrCryptoKeyConfigNewInvalidArgs.WithArgs(params)
}

func newCryptoKeyConfigFromJSON(b []byte) (*CryptoKeyConfig, error) {
	cfg := &CryptoKeyConfig{}
	if len(b) == 0 {
		return nil, errors.ErrCryptoKeyConfigNewEmptyArg
	}
	if err := json.Unmarshal(b, cfg); err != nil {
		return nil, errors.ErrCryptoKeyConfigNewFailedUnmarshal.WithArgs(err)
	}
	return cfg, nil
}

func newCryptoKeyConfigFromSecret(args []string) (*CryptoKeyConfig, error) {
	if len(args) != 2 {
		return nil, errors.ErrCryptoKeyConfigNewInvalidArgs.WithArgs(args)
	}

	return &CryptoKeyConfig{
		SignMethod: args[0],
		Secret:     args[1],
	}, nil
}

func (k *CryptoKeyConfig) validate() error {
	if k.ID == "" {
		return fmt.Errorf("no key id found")
	}
	switch k.Usage {
	case "":
		return fmt.Errorf("key usage is not set")
	case "verify", "sign", "both", "auto":
	default:
		return fmt.Errorf("key usage %q is invalid", k.Usage)
	}

	switch k.Source {
	case "":
		return fmt.Errorf("key source not found")
	case "config":
	case "env":
		switch k.EnvVarType {
		case "value", "file", "directory":
		case "":
			return fmt.Errorf("key source type for env not set")
		default:
			return fmt.Errorf("key source type %q is invalid", k.EnvVarType)
		}
	default:
		return fmt.Errorf("key source %q is invalid", k.Source)
	}

	switch k.Algorithm {
	case "hmac", "rsa", "ecdsa", "":
	default:
		return fmt.Errorf("key algorithm %q is invalid", k.Algorithm)
	}
	return nil
}

func ParseCryptoKeyConfigs(cfg string, log *zap.Logger) ([]*CryptoKeyConfig, error) {
	var keys []*CryptoKeyConfig
	defaultConfig := make(map[string]interface{})

	m := make(map[string]*CryptoKeyConfig)
	for _, s := range strings.Split(cfg, "\n") {
		log.Debug("XXXX", zap.String("line", s))
		var key *CryptoKeyConfig
		kid := defaultKeyID
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		r := csv.NewReader(strings.NewReader(s))
		r.Comma = ' '
		args, err := r.Read()
		if err != nil {
			return nil, err
		}
		log.Debug("XXXX", zap.Any("args", args))
		line := strings.Join(args, " ")

		if len(args) < 3 {
			return nil, fmt.Errorf("key config entry is too short: %s", strings.Join(args, line))
		}

		// First, identify key id.
		j := 0
		if args[0] == "crypto" {
			j = 1
		}

		nextEntry := false
		switch args[j] {
		case "default":
			nextEntry = true
			p := args[j+1:]
			switch p[0] {
			case "token":
				if len(p) != 3 {
					return nil, fmt.Errorf("key config entry has invalid default token settings: %s", line)
				}
				switch p[1] {
				case "name":
					defaultConfig["token_name"] = p[2]
				case "lifetime":
					lifetime, err := strconv.Atoi(p[2])
					if err != nil {
						return nil, fmt.Errorf("key config entry has invalid default token lifetime settings: %s, error: %v", line, err)
					}
					defaultConfig["token_lifetime"] = lifetime
				default:
					return nil, fmt.Errorf("key config entry has invalid default token settings: %s", line)
				}
			default:
				return nil, fmt.Errorf("key config entry has invalid default settings: %s", line)
			}
		case "key":
			if exists := reservedKeyConfigKeywords[args[j+1]]; !exists {
				kid = args[j+1]
			}
		default:
			return nil, fmt.Errorf("key config entry is invalid: %s", line)
		}

		if nextEntry {
			continue
		}

		// Next, register the key.
		if _, exists := m[kid]; !exists {
			key = &CryptoKeyConfig{}
			key.Seq = len(m)
			key.ID = kid
			m[kid] = key
			keys = append(keys, key)
		} else {
			key = m[kid]
		}

		// Iterate over the provided configuration line.
		max := len(args) - 1
		i := 0
		for i < max {
			remainder := max - i
			log.Debug("XXXX", zap.String("kid", kid), zap.Int("index", i), zap.String("arg", args[i]), zap.Int("remaining_args", remainder))

			if exists := reservedKeyConfigKeywords[args[i]]; exists && (remainder == 0) {
				return nil, fmt.Errorf("keyword %q must not be last", args[i])
			}

			switch args[i] {
			case "key":
				if exists := reservedKeyConfigKeywords[args[i+1]]; !exists {
					i++
				}
			case "token":
				if remainder != 2 {
					return nil, fmt.Errorf("token must be followed by its attributes")
				}
				switch args[i+1] {
				case "name":
					key.TokenName = args[i+2]
				case "lifetime":
					i, err := strconv.Atoi(args[i+2])
					if err != nil {
						return nil, fmt.Errorf("key config contains invalid token lifetime: %v", args[i+2])
					}
					key.TokenLifetime = i
				default:
					return nil, fmt.Errorf("key config contains invalid token property: %v", args[i+1])
				}
				i += 2
			case "verify", "sign", "both", "auto":
				key.Usage = args[i]
				if args[i+1] != "from" {
					if remainder > 1 {
						return nil, fmt.Errorf("key config line is invalid: %s", s)
					}
					key.Secret = args[i+1]
					key.Source = "config"
					key.Algorithm = "hmac"
					i++
				}
			default:
				return nil, fmt.Errorf("key config contains invalid argument: %s", args[i])
			}
			i++
		}
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("key config not found")
	}

	sort.Slice(keys, func(i, j int) bool {
		return keys[i].Seq < keys[j].Seq
	})

	return keys, nil
}
