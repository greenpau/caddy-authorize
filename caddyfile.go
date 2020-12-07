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

	jwtacl "github.com/greenpau/caddy-auth-jwt/pkg/acl"
	jwtauth "github.com/greenpau/caddy-auth-jwt/pkg/auth"
	jwtconfig "github.com/greenpau/caddy-auth-jwt/pkg/config"
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
//       }
//       auth_url <path>
//       disable auth_url_redirect_query
//       allow <field> <value...>
//       allow <field> <value...> with <get|post|put|patch|delete|all> to <uri|any>
//       allow <field> <value...> with <get|post|put|patch|delete|all>
//       allow <field> <value...> to <uri|any>
//       default <allow|deny>
//       validate path_acl
//     }
//
//     jwt allow roles admin editor viewer
//
func parseCaddyfileTokenValidator(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	p := jwtauth.Authorizer{
		PrimaryInstance: false,
		Context:         "default",
		TrustedTokens:   []*jwtconfig.CommonTokenConfig{},
		AccessList:      []*jwtacl.AccessListEntry{},
	}

	// logger := initPluginLogger()

	defaultDenyACL := true

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
			case "auth_url":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, fmt.Errorf("%s argument has no value", rootDirective)
				}
				if len(args) != 1 {
					return nil, fmt.Errorf("%s argument value of %s is unsupported", rootDirective, args[0])
				}
				p.AuthURLPath = args[0]
			case "trusted_public_key":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, fmt.Errorf("%s argument has no value", rootDirective)
				}
				if len(args) != 2 {
					return nil, fmt.Errorf("%s argument values are unsupported %v", rootDirective, args)
				}
				tokenRSAFiles := make(map[string]string)
				tokenRSAFiles[args[0]] = args[1]
				tokenConfigProps := make(map[string]interface{})
				tokenConfigProps["token_rsa_files"] = tokenRSAFiles
				tokenConfigJSON, err := json.Marshal(tokenConfigProps)
				if err != nil {
					return nil, h.Errf("auth backend %s subdirective failed to compile to JSON: %s", rootDirective, err.Error())
				}
				tokenConfig := &jwtconfig.CommonTokenConfig{}
				if err := json.Unmarshal(tokenConfigJSON, tokenConfig); err != nil {
					return nil, h.Errf("auth backend %s subdirective failed to compile to JSON: %s", rootDirective, err.Error())
				}
				p.TrustedTokens = append(p.TrustedTokens, tokenConfig)
			case "trusted_tokens":
				for nesting := h.Nesting(); h.NextBlock(nesting); {
					subDirective := h.Val()
					tokenConfigProps := make(map[string]interface{})
					for subNesting := h.Nesting(); h.NextBlock(subNesting); {
						backendArg := h.Val()
						switch backendArg {
						case "token_rsa_file":
							rsaArgs := h.RemainingArgs()
							if len(rsaArgs) != 2 {
								return nil, h.Errf("auth backend %s subdirective %s requires two arguments: key id and file path", subDirective, backendArg)
							}
							var tokenRSAFiles map[string]string
							if _, exists := tokenConfigProps["token_rsa_files"]; exists {
								tokenRSAFiles = tokenConfigProps["token_rsa_files"].(map[string]string)
							}
							if tokenRSAFiles == nil {
								tokenRSAFiles = make(map[string]string)
							}
							tokenRSAFiles[rsaArgs[0]] = rsaArgs[1]
							tokenConfigProps["token_rsa_files"] = tokenRSAFiles
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
					tokenConfig := &jwtconfig.CommonTokenConfig{}
					if err := json.Unmarshal(tokenConfigJSON, tokenConfig); err != nil {
						return nil, h.Errf("auth backend %s subdirective failed to compile to JSON: %s", subDirective, err.Error())
					}
					p.TrustedTokens = append(p.TrustedTokens, tokenConfig)
				}
			case "allow", "deny":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, fmt.Errorf("%s argument has no value", rootDirective)
				}
				if len(args) == 1 {
					return nil, fmt.Errorf("%s argument has insufficient values", rootDirective)
				}
				entry := jwtacl.NewAccessListEntry()
				if rootDirective == "allow" {
					entry.Allow()
				} else {
					entry.Deny()
				}
				mode := "roles"
				for i, arg := range args {
					if i == 0 {
						if err := entry.SetClaim(arg); err != nil {
							return nil, fmt.Errorf("%s argument claim key %s error: %s", rootDirective, arg, err)
						}
						continue
					}

					switch arg {
					case "with":
						mode = "method"
						continue
					case "to":
						mode = "path"
						continue
					}

					switch mode {
					case "roles":
						if err := entry.AddValue(arg); err != nil {
							return nil, fmt.Errorf("%s argument claim value %s error: %s", rootDirective, arg, err)
						}
					case "method":
						if err := entry.AddMethod(arg); err != nil {
							return nil, fmt.Errorf("%s argument http method %s error: %s", rootDirective, arg, err)
						}
						p.ValidateMethodPath = true
					case "path":
						if entry.Path != "" {
							return nil, fmt.Errorf("%s argument http path %s is already set", rootDirective, arg)
						}
						if err := entry.SetPath(arg); err != nil {
							return nil, fmt.Errorf("%s argument http path %s error: %s", rootDirective, arg, err)
						}
						p.ValidateMethodPath = true
					}
				}
				p.AccessList = append(p.AccessList, entry)
			case "disable":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, fmt.Errorf("%s argument has no value", rootDirective)
				}
				switch args[0] {
				case "auth_redirect_query":
					p.AuthRedirectQueryDisabled = true
				default:
					return nil, fmt.Errorf("%s argument %s is unsupported", rootDirective, args[0])
				}
			case "validate":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, fmt.Errorf("%s argument has no value", rootDirective)
				}
				switch args[0] {
				case "path_acl":
					p.ValidateAccessListPathClaim = true
					p.ValidateMethodPath = true
				default:
					return nil, fmt.Errorf("%s argument %s is unsupported", rootDirective, args[0])
				}
			case "option":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, fmt.Errorf("%s argument has no value", rootDirective)
				}
				if p.TokenValidatorOptions == nil {
					p.TokenValidatorOptions = jwtconfig.NewTokenValidatorOptions()
				}
				switch args[0] {
				case "validate_bearer_header":
					p.TokenValidatorOptions.ValidateBearerHeader = true
				default:
					return nil, fmt.Errorf("%s argument %s is unsupported", rootDirective, args[0])
				}
			case "enable":
				args := strings.Join(h.RemainingArgs(), " ")
				switch args {
				case "claim headers":
					p.PassClaimsWithHeaders = true
				default:
					return nil, h.Errf("unsupported directive for %s: %s", rootDirective, args)
				}
			case "default":
				if !h.NextArg() {
					return nil, h.Errf("%s argument has no value", rootDirective)
				}
				if h.Val() == "allow" {
					defaultDenyACL = false
				}
			case "forbidden":
				if !h.NextArg() {
					return nil, h.Errf("%s argument has no value", rootDirective)
				}
				p.ForbiddenURL = h.Val()
			case "user_identity":
				if !h.NextArg() {
					return nil, h.Errf("%s argument has no value", rootDirective)
				}
				p.UserIdentityField = h.Val()
			default:
				return nil, h.Errf("unsupported root directive: %s", rootDirective)
			}
		}
	}

	if p.Context == "" {
		return nil, h.Errf("context directive must not be empty")
	}

	if !defaultDenyACL {
		p.AccessList = append(p.AccessList, &jwtacl.AccessListEntry{
			Action: "allow",
			Claim:  "roles",
			Values: []string{"any"},
		})
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
