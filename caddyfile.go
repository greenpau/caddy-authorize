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
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"

	"github.com/greenpau/caddy-auth-jwt/pkg/acl"
	"github.com/greenpau/caddy-auth-jwt/pkg/authz"
	"github.com/greenpau/caddy-auth-jwt/pkg/kms"
	"github.com/greenpau/caddy-auth-jwt/pkg/utils"

	"go.uber.org/zap"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("jwt", parseCaddyfileTokenValidator)
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
//         }
//         rsa_file {
//           token_name <value>
//           token_rsa_file <path>
//         }
//         ecdsa_file {
//           token_name <value>
//           token_ecdsa_file <path>
//         }
//       }
//       set auth url <path>
//       set forbidden url <path>
//       set token sources <value...>
//       set user identity <claim_field>
//       disable auth redirect query
//       disable auth redirect
//       allow <field> <value...>
//       allow <field> <value...> with <get|post|put|patch|delete> to <uri>
//       allow <field> <value...> with <get|post|put|patch|delete>
//       allow <field> <value...> to <uri>
//       validate path acl
//       validate source address
//       validate bearer header
//       enable js redirect
//       enable strip token
//       inject headers with claims
//     }
//
func parseCaddyfileTokenValidator(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	p := authz.Authorizer{
		PrimaryInstance: false,
		Context:         "default",
		TrustedTokens:   []*kms.CryptoKeyConfig{},
		AccessListRules: []*acl.RuleConfiguration{},
	}

	log := utils.NewLogger()

	for h.Next() {
		for nesting := h.Nesting(); h.NextBlock(nesting); {
			rootDirective := h.Val()
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
					p.PrimaryInstance = true
				}
			case "context":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, fmt.Errorf("%s argument has no value", rootDirective)
				}
				if len(args) != 1 {
					return nil, fmt.Errorf("%s argument value of %s is unsupported", rootDirective, args[0])
				}
				p.Context = args[0]
			case "trusted_public_key", "trusted_rsa_public_key":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, fmt.Errorf("%s argument has no value", rootDirective)
				}
				if len(args) != 2 {
					return nil, fmt.Errorf("%s argument values are unsupported %v", rootDirective, args)
				}
				tokenRSAFiles := make(map[string]string)
				tokenRSAFiles[args[0]] = args[1]
				cryptoKeyConfigProps := make(map[string]interface{})
				cryptoKeyConfigProps["token_rsa_files"] = tokenRSAFiles
				cryptoKeyConfigJSON, err := json.Marshal(cryptoKeyConfigProps)
				if err != nil {
					return nil, h.Errf("auth backend %s subdirective failed to compile to JSON: %s", rootDirective, err.Error())
				}
				// TODO(greenpau): change to NewCryptoKeyConfig(cryptoKeyConfigJSON)
				cryptoKeyConfig := &kms.CryptoKeyConfig{}
				if err := json.Unmarshal(cryptoKeyConfigJSON, cryptoKeyConfig); err != nil {
					return nil, h.Errf("auth backend %s subdirective failed to compile to JSON: %s", rootDirective, err.Error())
				}
				p.TrustedTokens = append(p.TrustedTokens, cryptoKeyConfig)
			case "trusted_ecdsa_public_key":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, fmt.Errorf("%s argument has no value", rootDirective)
				}
				if len(args) != 2 {
					return nil, fmt.Errorf("%s argument values are unsupported %v", rootDirective, args)
				}
				tokenECDSAFiles := make(map[string]string)
				tokenECDSAFiles[args[0]] = args[1]
				cryptoKeyConfigProps := make(map[string]interface{})
				cryptoKeyConfigProps["token_ecdsa_files"] = tokenECDSAFiles
				cryptoKeyConfigJSON, err := json.Marshal(cryptoKeyConfigProps)
				if err != nil {
					return nil, h.Errf("auth backend %s subdirective failed to compile to JSON: %s", rootDirective, err.Error())
				}
				cryptoKeyConfig := &kms.CryptoKeyConfig{}
				if err := json.Unmarshal(cryptoKeyConfigJSON, cryptoKeyConfig); err != nil {
					return nil, h.Errf("auth backend %s subdirective failed to compile to JSON: %s", rootDirective, err.Error())
				}
				p.TrustedTokens = append(p.TrustedTokens, cryptoKeyConfig)
			case "trusted_tokens":
				for nesting := h.Nesting(); h.NextBlock(nesting); {
					subDirective := h.Val()
					cryptoKeyConfigProps := make(map[string]interface{})
					for subNesting := h.Nesting(); h.NextBlock(subNesting); {
						backendArg := h.Val()
						switch backendArg {
						case "token_rsa_file":
							rsaArgs := h.RemainingArgs()
							if len(rsaArgs) != 2 {
								return nil, h.Errf("auth backend %s subdirective %s requires two arguments: key id and file path", subDirective, backendArg)
							}
							var tokenRSAFiles map[string]string
							if _, exists := cryptoKeyConfigProps["token_rsa_files"]; exists {
								tokenRSAFiles = cryptoKeyConfigProps["token_rsa_files"].(map[string]string)
							}
							if tokenRSAFiles == nil {
								tokenRSAFiles = make(map[string]string)
							}
							tokenRSAFiles[rsaArgs[0]] = rsaArgs[1]
							cryptoKeyConfigProps["token_rsa_files"] = tokenRSAFiles
						case "token_ecdsa_file":
							args := h.RemainingArgs()
							if len(args) != 2 {
								return nil, h.Errf("auth backend %s subdirective %s requires two arguments: key id and file path", subDirective, backendArg)
							}
							var tokenECDSAFiles map[string]string
							if _, exists := cryptoKeyConfigProps["token_ecdsa_files"]; exists {
								tokenECDSAFiles = cryptoKeyConfigProps["token_ecdsa_files"].(map[string]string)
							}
							if tokenECDSAFiles == nil {
								tokenECDSAFiles = make(map[string]string)
							}
							tokenECDSAFiles[args[0]] = args[1]
							cryptoKeyConfigProps["token_ecdsa_files"] = tokenECDSAFiles
						default:
							if !h.NextArg() {
								return nil, h.Errf("auth backend %s subdirective %s has no value", subDirective, backendArg)
							}
							cryptoKeyConfigProps[backendArg] = h.Val()
						}
					}
					cryptoKeyConfigJSON, err := json.Marshal(cryptoKeyConfigProps)
					if err != nil {
						return nil, h.Errf("auth backend %s subdirective failed to compile to JSON: %s", subDirective, err.Error())
					}
					cryptoKeyConfig := &kms.CryptoKeyConfig{}
					if err := json.Unmarshal(cryptoKeyConfigJSON, cryptoKeyConfig); err != nil {
						return nil, h.Errf("auth backend %s subdirective failed to compile to JSON: %s", subDirective, err.Error())
					}
					p.TrustedTokens = append(p.TrustedTokens, cryptoKeyConfig)
				}
			case "allow", "deny":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, fmt.Errorf("%s argument has no value", rootDirective)
				}
				if len(args) == 1 {
					return nil, fmt.Errorf("%s argument has insufficient values", rootDirective)
				}
				rule := &acl.RuleConfiguration{}
				rule.Action = rootDirective + " log warn"
				mode := "field"
				var cond, matchPath, matchMethod string
				var matchAlways bool
				for _, arg := range args {
					switch arg {
					case "with":
						mode = "method"
						continue
					case "to":
						mode = "path"
						continue
					}
					switch mode {
					case "field":
						if arg == "*" || arg == "any" {
							matchAlways = true
						}
						cond += " " + arg
					case "method":
						matchMethod = "match method " + strings.ToUpper(arg)
						mode = "path"
					case "path":
						matchPath = "partial match path " + arg
						mode = "complete"
					default:
						fmt.Errorf("%s argument has invalid value: %v", rootDirective, args)
					}
				}
				if matchAlways {
					rule.Conditions = append(rule.Conditions, "always match "+cond)
				} else {
					rule.Conditions = append(rule.Conditions, "match "+cond)
				}
				if matchMethod != "" {
					rule.Conditions = append(rule.Conditions, matchMethod)
					p.ValidateMethodPath = true
				}
				if matchPath != "" {
					rule.Conditions = append(rule.Conditions, matchPath)
					p.ValidateMethodPath = true
				}
				log.Debug("acl rule", zap.String("action", rule.Action), zap.Any("conditions", rule.Conditions))
				p.AccessListRules = append(p.AccessListRules, rule)
			case "disable":
				args := strings.Join(h.RemainingArgs(), " ")
				args = strings.TrimSpace(args)
				switch args {
				case "auth redirect query":
					p.AuthRedirectQueryDisabled = true
				case "auth redirect":
					p.AuthRedirectDisabled = true
				case "":
					return nil, fmt.Errorf("%s argument has no value", rootDirective)
				default:
					return nil, fmt.Errorf("%s argument %q is unsupported", rootDirective, args)
				}
			case "validate":
				args := strings.Join(h.RemainingArgs(), " ")
				args = strings.TrimSpace(args)
				switch args {
				case "path acl":
					p.ValidateAccessListPathClaim = true
					p.ValidateMethodPath = true
				case "source address":
					p.ValidateSourceAddress = true
				case "bearer header":
					p.ValidateBearerHeader = true
				case "":
					return nil, fmt.Errorf("%s argument has no value", rootDirective)
				default:
					return nil, fmt.Errorf("%s argument %q is unsupported", rootDirective, args)
				}
			case "set":
				args := strings.Join(h.RemainingArgs(), " ")
				args = strings.TrimSpace(args)
				switch {
				case strings.HasPrefix(args, "token sources"):
					p.AllowedTokenSources = strings.Split(strings.TrimPrefix(args, "token sources "), " ")
				case strings.HasPrefix(args, "auth url"):
					p.AuthURLPath = strings.TrimPrefix(args, "auth url ")
				case strings.HasPrefix(args, "forbidden url "):
					p.ForbiddenURL = strings.TrimPrefix(args, "forbidden url ")
				case strings.HasPrefix(args, "user identity "):
					p.UserIdentityField = strings.TrimPrefix(args, "user identity ")
				case args == "":
					return nil, fmt.Errorf("%s argument has no value", rootDirective)
				default:
					return nil, fmt.Errorf("%s argument %q is unsupported", rootDirective, args)
				}
			case "enable":
				args := strings.Join(h.RemainingArgs(), " ")
				switch args {
				case "js redirect":
					p.RedirectWithJavascript = true
				case "strip token":
					p.StripTokenEnabled = true
				default:
					return nil, h.Errf("unsupported directive for %s: %s", rootDirective, args)
				}
			case "inject":
				args := strings.Join(h.RemainingArgs(), " ")
				switch args {
				case "headers with claims":
					p.PassClaimsWithHeaders = true
				default:
					return nil, h.Errf("unsupported directive for %s: %s", rootDirective, args)
				}
			default:
				return nil, h.Errf("unsupported root directive: %s", rootDirective)
			}
		}
	}

	if p.Context == "" {
		return nil, h.Errf("context directive must not be empty")
	}

	return caddyauth.Authentication{
		ProvidersRaw: caddy.ModuleMap{
			"jwt": caddyconfig.JSON(AuthMiddleware{Authorizer: &p}, nil),
		},
	}, nil
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
