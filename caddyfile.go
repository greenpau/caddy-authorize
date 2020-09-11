// Copyright 2020 Paul Greenberg @greenpau
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

package jwt

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func init() {
	httpcaddyfile.RegisterDirective("jwt", parseCaddyfileTokenValidator)
}

func initCaddyfileLogger() *zap.Logger {
	logAtom := zap.NewAtomicLevel()
	logAtom.SetLevel(zapcore.DebugLevel)
	logEncoderConfig := zap.NewProductionEncoderConfig()
	logEncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	logEncoderConfig.TimeKey = "time"
	logger := zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(logEncoderConfig),
		zapcore.Lock(os.Stdout),
		logAtom,
	))
	return logger

}

// parseCaddyfileTokenValidator sets up JWT token authorization plugin. Syntax:
//
//     jwt {
//       primary <yes|no>
//       context <default|name>
//       trusted_tokens {
//         static_secret {
//           token_name <value>
//           token_secret <value>
//           token_issuer <value>
//         }
//         rsa_file {
//           token_name <value>
//           token_rsa_file <path>
//           token_issuer <value>
//         }
//       }
//       auth_url <path>
//       allow <field> <value...>
//     }
//
//     jwt allow roles admin editor viewer
//
func parseCaddyfileTokenValidator(h httpcaddyfile.Helper) ([]httpcaddyfile.ConfigValue, error) {
	validator := AuthProvider{
		PrimaryInstance: false,
		Context:         "default",
		TrustedTokens:   []*CommonTokenConfig{},
		AuthURLPath:     "/auth",
		AccessList:      []*AccessListEntry{},
	}

	logger := initCaddyfileLogger()

	for h.Next() {
		for nesting := h.Nesting(); h.NextBlock(nesting); {
			rootDirective := h.Val()
			logger.Debug("stage 1", zap.Any("root_directive", rootDirective))
			switch rootDirective {
			case "primary":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, fmt.Errorf("%s argument has no value", rootDirective)
				}
				if !isSwitchArg(args[0]) {
					return nil, fmt.Errorf("%s argument value of %s is unsupported", rootDirective, args[0])
				}
				if isEnabledArg(args[0]) {
					validator.PrimaryInstance = true
				}
			case "context":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, fmt.Errorf("%s argument has no value", rootDirective)
				}
				if len(args) != 1 {
					return nil, fmt.Errorf("%s argument value of %s is unsupported", rootDirective, args[0])
				}
				validator.Context = args[0]
			case "auth_url":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, fmt.Errorf("%s argument has no value", rootDirective)
				}
				if len(args) != 1 {
					return nil, fmt.Errorf("%s argument value of %s is unsupported", rootDirective, args[0])
				}
				validator.AuthURLPath = args[0]
			case "trusted_tokens":
				for nesting := h.Nesting(); h.NextBlock(nesting); {
					subDirective := h.Val()
					tokenConfigProps := make(map[string]interface{})
					for subNesting := h.Nesting(); h.NextBlock(subNesting); {
						backendArg := h.Val()
						switch backendArg {
						case "token_rsa_file":
							// TODO: handle the parsinf of rsa files/keys
							if !h.NextArg() {
								return nil, h.Errf("auth backend %s subdirective %s has no value", subDirective, backendArg)
							}
							tokenConfigProps[backendArg] = h.Val()
						default:
							if !h.NextArg() {
								return nil, h.Errf("auth backend %s subdirective %s has no value", subDirective, backendArg)
							}
							tokenConfigProps[backendArg] = h.Val()
						}
					}
					tokenConfigJSON, err := json.Marshal(tokenConfigProps)
					if err != nil {
						return nil, h.Errf("auth backend %s subdirective failed to compile to JSON: %s", subDirective, err.Error())
					}
					tokenConfig := &CommonTokenConfig{}
					if err := json.Unmarshal(tokenConfigJSON, tokenConfig); err != nil {
						return nil, h.Errf("auth backend %s subdirective failed to compile to JSON: %s", subDirective, err.Error())
					}
					validator.TrustedTokens = append(validator.TrustedTokens, tokenConfig)
				}
			case "allow", "deny":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, fmt.Errorf("%s argument has no value", rootDirective)
				}
				if len(args) == 1 {
					return nil, fmt.Errorf("%s argument has insufficient values", rootDirective)
				}
				entry := NewAccessListEntry()
				if rootDirective == "allow" {
					entry.Allow()
				} else {
					entry.Deny()
				}
				for i, arg := range args {
					if i == 0 {
						if err := entry.SetClaim(arg); err != nil {
							return nil, fmt.Errorf("%s argument claim key %s error: %s", rootDirective, arg, err)
						}
						continue
					}
					if err := entry.AddValue(arg); err != nil {
						return nil, fmt.Errorf("%s argument claim value %s error: %s", rootDirective, arg, err)
					}
				}
				validator.AccessList = append(validator.AccessList, entry)
			default:
				return nil, h.Errf("unsupported root directive: %s", rootDirective)
			}
		}
	}

	if validator.AuthURLPath == "" {
		validator.AuthURLPath = "/auth"
	}
	if strings.HasSuffix(validator.AuthURLPath, "*") {
		return nil, h.Errf("path directive must not end with '*', got %s", validator.AuthURLPath)
	}
	if !strings.HasPrefix(validator.AuthURLPath, "/") {
		return nil, h.Errf("path directive must begin with '/', got %s", validator.AuthURLPath)
	}

	if validator.Context == "" {
		return nil, h.Errf("context directive must not be empty")
	}

	h.Reset()
	h.Next()
	pathMatcher := caddy.ModuleMap{
		"path": h.JSON(caddyhttp.MatchPath{"/*"}),
	}
	route := caddyhttp.Route{
		HandlersRaw: []json.RawMessage{caddyconfig.JSONModuleObject(validator, "handler", "jwt", nil)},
	}
	subroute := new(caddyhttp.Subroute)
	subroute.Routes = append([]caddyhttp.Route{route}, subroute.Routes...)
	return h.NewRoute(pathMatcher, subroute), nil
}

func isEnabledArg(s string) bool {
	if s == "yes" || s == "true" || s == "on" {
		return true
	}
	return false
}

func isSwitchArg(s string) bool {
	if s == "yes" || s == "true" || s == "on" {
		return true
	}
	if s == "no" || s == "false" || s == "off" {
		return true
	}
	return false
}
