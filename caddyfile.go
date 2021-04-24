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
//
//       crypto key token name <TOKEN_NAME>
//       crypto key <ID> token name <TOKEN_NAME>
//
//       crypto key verify <SHARED_SECRET>
//       crypto key verify from env <ENV_VAR_SHARED_SECRET>
//       crypto key <ID> verify <SHARED_SECRET>
//       crypto key <ID> verify from env <ENV_VAR_SHARED_SECRET>
//
//       crypto key <ID> verify from <directory|file> <PATH>
//       crypto key <ID> verify from env <NAME> as <directory|file|value>
//
//       set auth url <path>
//       set forbidden url <path>
//       set token sources <value...>
//       set user identity <claim_field>
//
//       disable auth redirect query
//       disable auth redirect
//
//       allow <field> <value...>
//       allow <field> <value...> with <get|post|put|patch|delete> to <uri>
//       allow <field> <value...> with <get|post|put|patch|delete>
//       allow <field> <value...> to <uri>
//
//       validate path acl
//       validate source address
//       validate bearer header
//
//       enable js redirect
//       enable strip token
//
//       inject headers with claims
//     }
//
func parseCaddyfileTokenValidator(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	p := authz.Authorizer{
		PrimaryInstance: false,
		Context:         "default",
		CryptoKeys:      []*kms.CryptoKeyConfig{},
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
			case "crypto":
				args := strings.Join(h.RemainingArgs(), " ")
				args = strings.TrimSpace(args)
				return nil, fmt.Errorf("%s argument value of %q is unsupported", rootDirective, args)
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
