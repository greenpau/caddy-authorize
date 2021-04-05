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
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
)

var (
	defaultKeyID             = "0"
	defaultTokenName         = "access_token"
	defaultTokenLifetime int = 900
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

// TokenConfig is common token-related configuration settings.
type TokenConfig struct {
	Name       string            `json:"token_name,omitempty" xml:"token_name" yaml:"token_name"`
	SignMethod string            `json:"token_sign_method,omitempty" xml:"token_sign_method,omitempty" yaml:"token_sign_method,omitempty"`
	Lifetime   int               `json:"token_lifetime,omitempty" xml:"token_lifetime" yaml:"token_lifetime"`
	EvalExpr   []string          `json:"token_eval_expr,omitempty" xml:"token_eval_expr" yaml:"token_eval_expr"`
	Secret     string            `json:"token_secret,omitempty" xml:"token_secret" yaml:"token_secret"`
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
}

// NewTokenConfig returns an instance of TokenConfig.
func NewTokenConfig(params ...interface{}) (*TokenConfig, error) {
	var argCount int
	var args []string

	for i, arg := range params {
		argCount++
		switch i {
		case 0:
			if arg == nil {
				return nil, errors.ErrTokenConfigNewArgTypeInvalid.WithArgs([]interface{}{})
			}
			switch v := arg.(type) {
			case string:
				if isMethodSupported(v) {
					args = append(args, v)
					break
				}
				return newTokenConfigFromJSON([]byte(v))
			case []uint8:
				return newTokenConfigFromJSON(v)
				//default:
				//	return nil, errors.ErrTokenConfigNewArgTypeInvalid.WithArgs(v)
			}
		default:
			switch v := arg.(type) {
			case string:
				args = append(args, v)
			}
		}
	}
	if argCount == 0 {
		return &TokenConfig{}, nil
	}

	if len(args) > 0 {
		if isMethodSupported(args[0]) {
			return newTokenConfigFromSecret(args)
		}
	}

	return nil, errors.ErrTokenConfigNewInvalidArgs.WithArgs(params)
}

func newTokenConfigFromJSON(b []byte) (*TokenConfig, error) {
	cfg := &TokenConfig{}
	if len(b) == 0 {
		return nil, errors.ErrTokenConfigNewEmptyArg
	}
	if err := json.Unmarshal(b, cfg); err != nil {
		return nil, errors.ErrTokenConfigNewFailedUnmarshal.WithArgs(err)
	}
	return cfg, nil
}

func newTokenConfigFromSecret(args []string) (*TokenConfig, error) {
	if len(args) != 2 {
		return nil, errors.ErrTokenConfigNewInvalidArgs.WithArgs(args)
	}

	return &TokenConfig{
		SignMethod: args[0],
		Secret:     args[1],
	}, nil
}
