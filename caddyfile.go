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

package authorize

import (
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"

	"github.com/greenpau/caddy-authorize/pkg/acl"
	"github.com/greenpau/caddy-authorize/pkg/authz"
	"github.com/greenpau/caddy-authorize/pkg/kms"
	"github.com/greenpau/caddy-authorize/pkg/shared/idp"
	cfgutils "github.com/greenpau/caddy-authorize/pkg/utils/cfg"
)

const badRepl string = "ERROR_BAD_REPL"

func init() {
	httpcaddyfile.RegisterHandlerDirective("authorize", getMiddlewareFromParseCaddyfile)
}

// parseCaddyfile sets up JWT token authorization plugin. Syntax:
//
//     authorize {
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
//       set redirect query parameter <value>
//       set redirect status <3xx>
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
//       bypass uri <exact|partial|prefix|suffix|regex> <uri_path>
//
//       inject headers with claims
//
//       inject header <header_name> from <field_name>
//
//       with basic auth [realm <realm_name>] [context <context_name>]
//       with api key auth [realm <realm_name>] [context <context_name>]
//     }
//
func parseCaddyfile(h httpcaddyfile.Helper) (*authz.Authorizer, error) {
	var cryptoKeyConfig, cryptoKeyStoreConfig []string
	var cryptoKeyConfigFound, cryptoKeyStoreConfigFound bool
	var idpConfig []string
	p := authz.Authorizer{
		PrimaryInstance:  false,
		Context:          "default",
		CryptoKeyConfigs: []*kms.CryptoKeyConfig{},
		AccessListRules:  []*acl.RuleConfiguration{},
	}
	repl := caddy.NewReplacer()

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
				encodedArgs := cfgutils.EncodeArgs(args)
				encodedArgs = repl.ReplaceAll(encodedArgs, badRepl)
				cryptoKeyConfig = append(cryptoKeyConfig, encodedArgs)
				switch args[0] {
				case "key":
					cryptoKeyConfigFound = true
				case "default":
					cryptoKeyStoreConfig = append(cryptoKeyStoreConfig, encodedArgs)
					cryptoKeyStoreConfigFound = true
				default:
					return nil, h.Errf("%s directive value of %q is unsupported", rootDirective, strings.Join(args, " "))
				}
			case "acl":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, h.Errf("%s directive has no value", rootDirective)
				}
				switch args[0] {
				case "rule":
					if len(args) > 1 {
						return nil, h.Errf("%s directive %q is too long", rootDirective, strings.Join(args, " "))
					}
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
				case "default":
					if len(args) != 2 {
						return nil, h.Errf("%s directive %q is too long", rootDirective, strings.Join(args, " "))
					}
					rule := &acl.RuleConfiguration{
						Conditions: []string{"always match iss any"},
					}
					switch args[1] {
					case "allow", "deny":
						rule.Action = args[1]
					default:
						return nil, h.Errf("%s directive %q must have either allow or deny", rootDirective, strings.Join(args, " "))
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
				case "login hint":
					p.LoginHintValidators = []string{"disabled"}
				case "":
					return nil, h.Errf("%s directive has no value", rootDirective)
				default:
					return nil, h.Errf("%s directive %q is unsupported", rootDirective, args)
				}
			case "bypass":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, h.Errf("%s directive has no value", rootDirective)
				}
				if len(args) != 3 {
					return nil, h.Errf("%s %s is invalid", rootDirective, cfgutils.EncodeArgs(args))
				}
				if args[0] != "uri" {
					return nil, h.Errf("%s %s is invalid", rootDirective, cfgutils.EncodeArgs(args))
				}
				bc := &authz.BypassConfig{
					MatchType: args[1],
					URI:       args[2],
				}
				if err := bc.Validate(); err != nil {
					return nil, h.Errf("%s %s erred: %v", rootDirective, cfgutils.EncodeArgs(args), err)
				}
				p.BypassConfigs = append(p.BypassConfigs, bc)
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
				case strings.HasPrefix(args, "redirect query parameter "):
					p.AuthRedirectQueryParameter = strings.TrimPrefix(args, "redirect query parameter ")
				case strings.HasPrefix(args, "redirect status "):
					n, err := strconv.Atoi(strings.TrimPrefix(args, "redirect status "))
					if err != nil {
						return nil, h.Errf("%s %s directive failed: %v", rootDirective, args, err)
					}
					if n < 300 || n > 308 {
						return nil, h.Errf("%s %s directive contains invalid value", rootDirective, args)
					}
					p.AuthRedirectStatusCode = n
				case strings.HasPrefix(args, "user identity "):
					p.UserIdentityField = strings.TrimPrefix(args, "user identity ")
				case args == "":
					return nil, h.Errf("%s directive has no value", rootDirective)
				default:
					return nil, h.Errf("%s directive %q is unsupported", rootDirective, args)
				}
			case "enable":
				args := strings.Join(h.RemainingArgs(), " ")
				switch {
				case strings.HasPrefix(args, "js redirect"):
					p.RedirectWithJavascript = true
				case strings.HasPrefix(args, "strip token"):
					p.StripTokenEnabled = true
				case strings.HasPrefix(args, "login hint"):
					remainingArguments := strings.TrimPrefix(args, "login hint ")

					switch {
					case strings.HasPrefix(remainingArguments, "with"):
						remainingArguments = strings.TrimPrefix(remainingArguments, "with ")
						validationArguments := strings.Split(remainingArguments, " ")

						for _, token := range validationArguments {
							switch token {
							case "alphanumeric", "email", "phone":
								continue
							default:
								return nil, h.Errf("%s login hint validator is unsupported", token)
							}
						}
						p.LoginHintValidators = validationArguments
						break
					default:
						p.LoginHintValidators = []string{"email", "phone", "alphanumeric"}
						break
					}

				default:
					return nil, h.Errf("unsupported directive for %s: %s", rootDirective, args)
				}
			case "inject":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, h.Errf("%s directive has no value", rootDirective)
				}
				switch {
				case cfgutils.EncodeArgs(args) == "headers with claims":
					p.PassClaimsWithHeaders = true
				case args[0] == "header":
					if len(args) != 4 {
						return nil, h.Errf("%s directive %q is invalid", rootDirective, cfgutils.EncodeArgs(args))
					}
					if args[2] != "from" {
						return nil, h.Errf("%s directive %q has invalid syntax", rootDirective, cfgutils.EncodeArgs(args))
					}
					cfg := &authz.HeaderInjectionConfig{
						Header: args[1],
						Field:  args[3],
					}
					if err := cfg.Validate(); err != nil {
						return nil, h.Errf("%s %s erred: %v", rootDirective, cfgutils.EncodeArgs(args), err)
					}
					p.HeaderInjectionConfigs = append(p.HeaderInjectionConfigs, cfg)
				default:
					return nil, h.Errf("unsupported directive for %s: %s", rootDirective, cfgutils.EncodeArgs(args))
				}
			case "with":
				args := h.RemainingArgs()
				switch {
				case strings.HasPrefix(strings.Join(args, " "), "basic auth"):
					idpConfig = append(idpConfig, cfgutils.EncodeArgs(args))
				case strings.HasPrefix(strings.Join(args, " "), "api key auth"):
					idpConfig = append(idpConfig, cfgutils.EncodeArgs(args))
				default:
					return nil, h.Errf("%s directive %q is unsupported", rootDirective, args)
				}
			default:
				return nil, h.Errf("unsupported root directive: %s", rootDirective)
			}
		}
	}

	if p.Context == "" {
		return nil, h.Errf("context directive must not be empty")
	}

	if cryptoKeyConfigFound {
		configs, err := kms.ParseCryptoKeyConfigs(strings.Join(cryptoKeyConfig, "\n"))
		if err != nil {
			return nil, h.Errf("crypto key config error: %v", err)
		}
		p.CryptoKeyConfigs = configs
	}

	if cryptoKeyStoreConfigFound {
		configs, err := kms.ParseCryptoKeyStoreConfig(strings.Join(cryptoKeyStoreConfig, "\n"))
		if err != nil {
			return nil, h.Errf("crypto key store config error: %v", err)
		}
		p.CryptoKeyStoreConfig = configs
	}

	if len(idpConfig) > 0 {
		config, err := idp.ParseIdentityProviderConfig(idpConfig)
		if err != nil {
			return nil, h.Errf("identity provider config error: %v", err)
		}
		p.IdentityProviderConfig = config
	}

	return &p, nil
}

func getMiddlewareFromParseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	p, err := parseCaddyfile(h)
	if err != nil {
		return nil, err
	}

	return caddyauth.Authentication{
		ProvidersRaw: caddy.ModuleMap{
			"authorize": caddyconfig.JSON(AuthMiddleware{Authorizer: p}, nil),
		},
	}, nil
}
