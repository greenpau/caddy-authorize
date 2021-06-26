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
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"

	"github.com/greenpau/caddy-auth-jwt/pkg/acl"
	"github.com/greenpau/caddy-auth-jwt/pkg/authz"
	"github.com/greenpau/caddy-auth-jwt/pkg/kms"
	"github.com/greenpau/caddy-auth-jwt/pkg/utils/cfgutils"
	// "go.uber.org/zap"
)

const badRepl string = "ERROR_BAD_REPL"

func init() {
	httpcaddyfile.RegisterHandlerDirective("jwt", parseCaddyfile)
}

// parseCaddyfile sets up JWT token authorization plugin. Syntax:
//
//     jwt {
//       primary <yes|no>
//       context <default|name>
//
//       crypto default token name <TOKEN_NAME>
//       crypto default token lifetime <SECONDS>
//
//       crypto key token name <TOKEN_NAME>
//       crypto key <ID> token name <TOKEN_NAME>
//
//       crypto key <verify|sign|sign-verify|auto> <SHARED_SECRET>
//       crypto key <verify|sign|sign-verify|auto> from env <ENV_VAR_WITH_KEY>
//
//       crypto key <ID> <verify|sign|sign-verify|auto> <SHARED_SECRET>
//       crypto key <ID> <verify|sign|sign-verify|auto> from <directory|file> <PATH>
//
//       crypto key <ID> <verify|sign|sign-verify|auto> from env <ENV_VAR_WITH_KEY>
//       crypto key <ID> <verify|sign|sign-verify|auto> from env <ENV_VAR_NAME> as <directory|file>
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
//       acl rule {
//         comment <value>
//         [exact|partial|prefix|suffix|regex|always] match <field> <value> ... <valueN>
//         [exact|partial|prefix|suffix|regex|always] match method <http_method_name>
//         [exact|partial|prefix|suffix|regex|always] match path <http_path_uri>
//         <allow|deny> [stop] [counter] [log <error|warn|info|debug>]
//       }
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
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var cryptoKeyConfig []string
	p := authz.Authorizer{
		PrimaryInstance:  false,
		Context:          "default",
		CryptoKeyConfigs: []*kms.CryptoKeyConfig{},
		AccessListRules:  []*acl.RuleConfiguration{},
	}
	repl := caddy.NewReplacer()
	// log := utils.NewLogger()

	for h.Next() {
		for nesting := h.Nesting(); h.NextBlock(nesting); {
			rootDirective := h.Val()
			switch rootDirective {
			case "primary":
				v, err := cfgutils.ParseBoolArg(strings.Join(h.RemainingArgs(), " "))
				if err != nil {
					return nil, h.Errf("%s directive error: %v", rootDirective, err)
				}
				p.PrimaryInstance = v
			case "context":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, h.Errf("%s directive has no value", rootDirective)
				}
				if len(args) != 1 {
					return nil, h.Errf("%s directive value of %s is unsupported", rootDirective, args[0])
				}
				p.Context = args[0]
			case "crypto":
				args := h.RemainingArgs()
				if len(args) < 3 {
					return nil, h.Errf("%s directive %q is too short", rootDirective, strings.Join(args, " "))
				}
				switch args[0] {
				case "key", "default":
					encodedArgs := cfgutils.EncodeArgs(args)
					encodedArgs = repl.ReplaceAll(encodedArgs, badRepl)
					cryptoKeyConfig = append(cryptoKeyConfig, encodedArgs)
				default:
					return nil, h.Errf("%s directive value of %q is unsupported", rootDirective, strings.Join(args, " "))
				}
			case "acl":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, h.Errf("%s directive has no value", rootDirective)
				}
				if len(args) > 1 {
					return nil, h.Errf("%s directive %q is too long", rootDirective, strings.Join(args, " "))
				}
				switch args[0] {
				case "rule":
					rule := &acl.RuleConfiguration{}
					for subNesting := h.Nesting(); h.NextBlock(subNesting); {
						k := h.Val()
						rargs := h.RemainingArgs()
						if len(args) == 0 {
							return nil, h.Errf("%s %s directive %v has no values", rootDirective, args[0], k)
						}
						rargs = append([]string{k}, rargs...)
						switch k {
						case "comment":
							rule.Comment = cfgutils.EncodeArgs(rargs)
						case "allow", "deny":
							rule.Action = cfgutils.EncodeArgs(rargs)
						default:
							rule.Conditions = append(rule.Conditions, cfgutils.EncodeArgs(rargs))
						}
					}
					p.AccessListRules = append(p.AccessListRules, rule)
				default:
					return nil, h.Errf("%s directive value of %q is unsupported", rootDirective, strings.Join(args, " "))
				}
			case "allow", "deny":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, h.Errf("%s directive has no value", rootDirective)
				}
				if len(args) < 2 {
					return nil, h.Errf("%s directive %q is too short", rootDirective, strings.Join(args, " "))
				}
				rule := &acl.RuleConfiguration{}
				// rule.Action = cfgutils.EncodeArgs([]string{rootDirective, "log", "warn"})

				mode := "field"
				var cond []string
				var matchMethod, matchPath string
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
						cond = append(cond, arg)
					case "method":
						matchMethod = strings.ToUpper(arg)
						mode = "path"
					case "path":
						matchPath = arg
						mode = "complete"
					default:
						return nil, h.Errf("%s directive value of %q is unsupported", rootDirective, strings.Join(args, " "))
					}
				}
				if matchAlways {
					rule.Conditions = append(rule.Conditions, cfgutils.EncodeArgs(append([]string{"always", "match"}, cond...)))
				} else {
					rule.Conditions = append(rule.Conditions, cfgutils.EncodeArgs(append([]string{"match"}, cond...)))
				}
				if matchMethod != "" {
					rule.Conditions = append(rule.Conditions, cfgutils.EncodeArgs([]string{"match", "method", matchMethod}))
					p.ValidateMethodPath = true
				}
				if matchPath != "" {
					rule.Conditions = append(rule.Conditions, cfgutils.EncodeArgs([]string{"partial", "match", "path", matchPath}))
					p.ValidateMethodPath = true
				}
				if rootDirective == "allow" {
					rule.Action = cfgutils.EncodeArgs([]string{rootDirective, "log", "debug"})
				} else {
					rule.Action = cfgutils.EncodeArgs([]string{rootDirective, "stop", "log", "warn"})
				}
				// log.Debug("acl rule", zap.String("action", rule.Action), zap.Any("conditions", rule.Conditions))
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
					return nil, h.Errf("%s directive has no value", rootDirective)
				default:
					return nil, h.Errf("%s directive %q is unsupported", rootDirective, args)
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
					return nil, h.Errf("%s directive has no value", rootDirective)
				default:
					return nil, h.Errf("%s directive %q is unsupported", rootDirective, args)
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
					return nil, h.Errf("%s directive has no value", rootDirective)
				default:
					return nil, h.Errf("%s directive %q is unsupported", rootDirective, args)
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

	if len(cryptoKeyConfig) != 0 {
		configs, err := kms.ParseCryptoKeyConfigs(strings.Join(cryptoKeyConfig, "\n"))
		if err != nil {
			return nil, h.Errf("crypto key config error: %v", err)
		}
		p.CryptoKeyConfigs = configs
	}

	return caddyauth.Authentication{
		ProvidersRaw: caddy.ModuleMap{
			"jwt": caddyconfig.JSON(AuthMiddleware{Authorizer: &p}, nil),
		},
	}, nil
}
