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
	"encoding/csv"
	"fmt"
	"github.com/greenpau/caddy-authorize/pkg/errors"
	cfgutils "github.com/greenpau/caddy-authorize/pkg/utils/cfg"
	"os"
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
		"crypto":      true,
		"key":         true,
		"sign":        true,
		"verify":      true,
		"sign-verify": true,
		"auto":        true,
		"and":         true,
		"token":       true,
		"lifetime":    true,
		"from":        true,
		"env":         true,
		"as":          true,
	}
	reservedUsageKeywords = map[string]bool{
		"sign":        true,
		"verify":      true,
		"sign-verify": true,
		"auto":        true,
	}
)

// CryptoKeyConfig is common token-related configuration settings.
type CryptoKeyConfig struct {
	// Seq is the order in which a key would be processed.
	Seq int `json:"seq,omitempty" xml:"seq,omitempty" yaml:"seq,omitempty"`
	// ID is the key ID, aka kid.
	ID string `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	// Usage is the intended key usage. The values are: sign, verify, both,
	// or auto.
	Usage string `json:"usage,omitempty" xml:"usage,omitempty" yaml:"usage,omitempty"`
	// TokenName is the token name associated with the key.
	TokenName string `json:"token_name,omitempty" xml:"token_name,omitempty" yaml:"token_name,omitempty"`
	// Source is either config or env.
	Source string `json:"source,omitempty" xml:"source,omitempty" yaml:"source,omitempty"`
	// Algorithm is either hmac, rsa, or ecdsa.
	Algorithm string `json:"algorithm,omitempty" xml:"algorithm,omitempty" yaml:"algorithm,omitempty"`
	// EnvVarName is the name of environment variables holding either the value of
	// a key or the path a directory or file containing a key.
	EnvVarName string `json:"env_var_name,omitempty" xml:"env_var_name,omitempty" yaml:"env_var_name,omitempty"`
	// EnvVarType indicates how to interpret the value found in the EnvVarName. If
	// it is blank, then the assumption is the environment variable value
	// contains either public or private key.
	EnvVarType string `json:"env_var_type,omitempty" xml:"env_var_type,omitempty" yaml:"env_var_type,omitempty"`
	// EnvVarValue is the value associated with the environment variable set by EnvVarName.
	EnvVarValue string `json:"env_var_value,omitempty" xml:"env_var_value,omitempty" yaml:"env_var_value,omitempty"`
	// FilePath is the path of a file containing either private or public key.
	FilePath string `json:"file_path,omitempty" xml:"file_path,omitempty" yaml:"file_path,omitempty"`
	// DirPath is the path to a directory containing crypto keys.
	DirPath string `json:"dir_path,omitempty" xml:"dir_path,omitempty" yaml:"dir_path,omitempty"`
	// TokenLifetime is the expected token grant lifetime in seconds.
	TokenLifetime int `json:"token_lifetime,omitempty" xml:"token_lifetime,omitempty" yaml:"token_lifetime,omitempty"`
	// Secret is the shared key used with HMAC algorithm.
	Secret string `json:"token_secret,omitempty" xml:"token_secret" yaml:"token_secret"`
	// PreferredSignMethod is the preferred method to sign tokens, e.g.
	// all HMAC keys could use HS256, HS384, and HS512 methods. By default,
	// the preferred method is HS512. However, one may prefer using HS256.
	PreferredSignMethod string `json:"token_sign_method,omitempty" xml:"token_sign_method,omitempty" yaml:"token_sign_method,omitempty"`
	// EvalExpr is a list of expressions evaluated whether a specific key
	// should be used for signing and verification.
	EvalExpr []string `json:"token_eval_expr,omitempty" xml:"token_eval_expr" yaml:"token_eval_expr"`
	// parsed indicated whether the key was parsed via config.
	parsed bool
	// validated indicated whether the key config was validated.
	validated bool
}

// ToString returns string representation of a crypto key config.
func (k *CryptoKeyConfig) ToString() string {
	var sb strings.Builder
	sb.WriteString("key config for kid: " + k.ID)
	if k.Usage != "" {
		sb.WriteString(", usage: " + k.Usage)
	}
	if k.Source != "" {
		sb.WriteString(", source: " + k.Source)
	}
	if k.Secret != "" {
		sb.WriteString(", secret: " + k.Secret)
	}
	if k.Algorithm != "" {
		sb.WriteString(", algo: " + k.Algorithm)
	}
	if k.EnvVarName != "" {
		sb.WriteString(", env var as " + k.EnvVarType + ": " + k.EnvVarName)
	}
	if k.FilePath != "" {
		sb.WriteString(", file path: " + k.FilePath)
	}
	if k.DirPath != "" {
		sb.WriteString(", dir path: " + k.DirPath)
	}
	if k.validated || k.parsed {
		sb.WriteString(", flags:")
		if k.parsed {
			sb.WriteString(" parsed")
		}
		if k.validated {
			sb.WriteString(" validated")
		}
	}
	if k.TokenName != "" {
		sb.WriteString(", token name=" + k.TokenName)
	}
	if k.TokenLifetime != 0 {
		sb.WriteString(fmt.Sprintf(" lifetime=%d", k.TokenLifetime))
	}
	return sb.String()
}

func (k *CryptoKeyConfig) loadEnvVar() error {
	v := os.Getenv(k.EnvVarName)
	v = strings.TrimSpace(v)
	if v == "" {
		return errors.ErrCryptoKeyConfigEmptyEnvVar.WithArgs(k.EnvVarName)
	}
	k.EnvVarValue = v
	return nil
}

func (k *CryptoKeyConfig) validate() error {
	switch k.Usage {
	case "verify", "sign", "sign-verify", "auto":
	case "":
		return fmt.Errorf("key usage is not set")
	default:
		return fmt.Errorf("key usage %q is invalid", k.Usage)
	}

	switch k.Source {
	case "":
		return fmt.Errorf("key source not found")
	case "config":
	case "env":
		switch k.EnvVarType {
		case "key", "file", "directory":
		case "":
			return fmt.Errorf("key source type for env not set")
		default:
			return fmt.Errorf("key source type %q for env is invalid", k.EnvVarType)
		}
	default:
		return fmt.Errorf("key source %q is invalid", k.Source)
	}

	switch k.Algorithm {
	case "hmac", "rsa", "ecdsa", "":
	default:
		return fmt.Errorf("key algorithm %q is invalid", k.Algorithm)
	}
	k.validated = true
	return nil
}

// ParseCryptoKeyStoreConfig parses crypto key store default configuration,
// e.g. default token name and configuration.
func ParseCryptoKeyStoreConfig(cfg string) (map[string]interface{}, error) {
	m := make(map[string]interface{})
	for _, line := range strings.Split(cfg, "\n") {
		args, err := cfgutils.DecodeArgs(line)
		if err != nil {
			return nil, err
		}
		if len(args) < 4 {
			return nil, errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(line, "too few arguments")
		}
		if args[0] != "default" {
			return nil, errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(line, "must be prefixed with 'crypto default' keywords")
		}
		switch args[1] {
		case "token":
			switch args[2] {
			case "name":
				m["token_name"] = args[3]
			case "lifetime":
				lifetime, err := strconv.Atoi(args[3])
				if err != nil {
					return nil, errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(line, err)
				}
				m["token_lifetime"] = lifetime
			default:
				return nil, errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(line, "contains unsupported 'crypto default token' parameter: %s", args[2])
			}
		default:
			return nil, errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(line, fmt.Sprintf("contains unsupported 'crypto default' keyword: %s", args[1]))
		}
	}
	return m, nil
}

// ParseCryptoKeyConfigs parses crypto key configurations.
func ParseCryptoKeyConfigs(cfg string) ([]*CryptoKeyConfig, error) {
	var cursor int
	var keys []*CryptoKeyConfig
	defaultConfig := make(map[string]interface{})
	// m := make(map[string]*CryptoKeyConfig)
	for _, s := range strings.Split(cfg, "\n") {
		var key *CryptoKeyConfig
		var keyUsage string
		kid := defaultKeyID
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}

		r := csv.NewReader(strings.NewReader(s))
		r.Comma = ' '
		args, err := r.Read()
		if err != nil {
			return nil, errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(s, err)
		}

		line := strings.Join(args, " ")
		if len(args) < 3 {
			return nil, errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(line, "entry is too short")
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
					return nil, errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(line, "default token setting too short")
				}
				switch p[1] {
				case "name":
					defaultConfig["token_name"] = p[2]
				case "lifetime":
					lifetime, err := strconv.Atoi(p[2])
					if err != nil {
						return nil, errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(line, err)
					}
					defaultConfig["token_lifetime"] = lifetime
				default:
					return nil, errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(line, "unknown default token setting")
				}
			default:
				return nil, errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(line, "unknown default setting")
			}
		case "key":
			if exists := reservedKeyConfigKeywords[args[j+1]]; !exists {
				kid = args[j+1]
			}
		default:
			return nil, errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(line, "bad syntax")
		}

		if nextEntry {
			continue
		}

		for _, arg := range args {
			if _, exists := reservedUsageKeywords[arg]; exists {
				keyUsage = arg
				break
			}
		}

		// Next, register the key.
		var curKey *CryptoKeyConfig
		if len(keys) > 0 {
			curKey = keys[cursor]
		}
		switch {
		case len(keys) == 0:
			k := &CryptoKeyConfig{}
			k.Seq = len(keys)
			k.ID = kid
			keys = append(keys, k)
			key = k
			cursor = len(keys) - 1
		case curKey.ID != kid:
			k := &CryptoKeyConfig{}
			k.Seq = len(keys)
			k.ID = kid
			keys = append(keys, k)
			key = k
			cursor = len(keys) - 1
		case curKey.Usage != "" && keyUsage != "":
			if (curKey.Usage == "verify" && keyUsage == "sign") || (curKey.Usage == "sign" && keyUsage == "verify") ||
				(curKey.Usage == "auto" && keyUsage == "auto") || (curKey.Usage == "sign-verify" && keyUsage == "sign-verify") {
				nk := &CryptoKeyConfig{}
				nk.Seq = len(keys)
				nk.ID = kid
				nk.TokenName = curKey.TokenName
				nk.TokenLifetime = curKey.TokenLifetime
				key = nk
				keys = append(keys, nk)
				cursor = len(keys) - 1
			} else {
				key = curKey
			}
		default:
			key = curKey
		}

		// Iterate over the provided configuration line.
		max := len(args) - 1
		i := 0
		// for i < max {
		for i < len(args) {
			remainder := max - i
			if exists := reservedKeyConfigKeywords[args[i]]; exists && (remainder == 0) {
				return nil, errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(line, "reserved keyword must not be last")
			}

			switch args[i] {
			case "crypto":
			case "key":
				if exists := reservedKeyConfigKeywords[args[i+1]]; !exists {
					i++
				}
			case "token":
				if remainder < 2 {
					return nil, errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(line, "token must be followed by its attributes")
				}
				switch args[i+1] {
				case "name":
					key.TokenName = args[i+2]
				case "lifetime":
					i, err := strconv.Atoi(args[i+2])
					if err != nil {
						return nil, errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(line, err)
					}
					key.TokenLifetime = i
				default:
					return nil, errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(line, "unknown key token setting")
				}
				i += 2
			case "verify", "sign", "sign-verify", "auto":
				if key.Usage != "" {
					return nil, errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(line, "duplicate key id")
				}
				key.Usage = args[i]
				if args[i+1] != "from" {
					if remainder > 1 {
						return nil, errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(line, "bad syntax")
					}
					key.Secret = args[i+1]
					key.Source = "config"
					key.Algorithm = "hmac"
					i++
					break
				}
				switch remainder {
				case 3:
					switch args[i+2] {
					case "file":
						key.Source = "config"
						key.FilePath = args[i+3]
					case "directory":
						key.Source = "config"
						key.DirPath = args[i+3]
					case "env":
						key.Source = "env"
						key.EnvVarName = args[i+3]
						key.EnvVarType = "key"
						if err := key.loadEnvVar(); err != nil {
							return nil, errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(line, err)
						}
					default:
						return nil, errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(line, "bad syntax")
					}
					i += 3
				case 5:
					if args[i+2] != "env" || args[i+4] != "as" {
						return nil, errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(line, "bad syntax")
					}
					key.EnvVarName = args[i+3]
					switch args[i+5] {
					case "file", "directory", "key":
						key.Source = "env"
						key.EnvVarType = args[i+5]
						if err := key.loadEnvVar(); err != nil {
							return nil, errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(line, err)
						}
					default:
						return nil, errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(line, "bad syntax")
					}
					i += 5
				default:
					return nil, errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(line, "bad syntax")
				}
			default:
				return nil, errors.ErrCryptoKeyConfigEntryInvalid.WithArgs(line, "invalid argument")
			}
			i++
		}
	}

	if len(keys) == 0 {
		return nil, errors.ErrCryptoKeyConfigNoConfigFound
	}

	sort.Slice(keys, func(i, j int) bool {
		return keys[i].Seq < keys[j].Seq
	})

	for _, kcfg := range keys {
		if kcfg.TokenName == "" {
			if _, exists := defaultConfig["token_name"]; exists {
				kcfg.TokenName = defaultConfig["token_name"].(string)
			} else {
				kcfg.TokenName = defaultTokenName
			}
		}
		if kcfg.TokenLifetime == 0 {
			if _, exists := defaultConfig["token_lifetime"]; exists {
				kcfg.TokenLifetime = defaultConfig["token_lifetime"].(int)
			} else {
				kcfg.TokenLifetime = defaultTokenLifetime
			}
		}
		if err := kcfg.validate(); err != nil {
			return nil, errors.ErrCryptoKeyConfigKeyInvalid.WithArgs(kcfg.Seq, err)
		}
		kcfg.parsed = true
	}
	return keys, nil
}
