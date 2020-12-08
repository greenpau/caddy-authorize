# caddy-auth-jwt

<a href="https://github.com/greenpau/caddy-auth-jwt/actions/" target="_blank"><img src="https://github.com/greenpau/caddy-auth-jwt/workflows/build/badge.svg?branch=main"></a>
<a href="https://pkg.go.dev/github.com/greenpau/caddy-auth-jwt" target="_blank"><img src="https://img.shields.io/badge/godoc-reference-blue.svg"></a>
<a href="https://caddy.community" target="_blank"><img src="https://img.shields.io/badge/community-forum-ff69b4.svg"></a>

JWT Authorization Plugin for [Caddy v2](https://github.com/caddyserver/caddy).

Please see other relevant plugins:
* [caddy-auth-portal](https://github.com/greenpau/caddy-auth-portal)
* [caddy-trace](https://github.com/greenpau/caddy-trace)

Please show your appreciation for this work and :star: :star: :star:

This work is inspired by [BTBurke/caddy-jwt](https://github.com/BTBurke/caddy-jwt).
Many thanks to @BTBurke and other contributors to the plugin.

Please ask questions either here or via LinkedIn. I am happy to help you! @greenpau.

<!-- begin-markdown-toc -->
## Table of Contents

* [Ask Questions](#ask-questions)
* [Overview](#overview)
* [Limitations](#limitations)
* [Plugin Users](#plugin-users)
  * [Getting Started](#getting-started)
    * [JSON Configuration](#json-configuration)
    * [Caddyfile](#caddyfile)
* [Verification with RSA Public Keys](#verification-with-rsa-public-keys)
* [Auto-Redirect URL](#auto-redirect-url)
* [Plugin Developers](#plugin-developers)
* [Role-based Access Control and Access Lists](#role-based-access-control-and-access-lists)
  * [Sources of Role Information](#sources-of-role-information)
  * [Anonymous Role](#anonymous-role)
  * [Granting Access with Access Lists](#granting-access-with-access-lists)
  * [Default Allow ACL](#default-allow-acl)
  * [HTTP Method and Path in ACLs](#http-method-and-path-in-acls)
  * [Forbidden Access](#forbidden-access)
* [Path-Based Access Lists](#path-based-access-lists)
* [Pass Token Claims in HTTP Headers](#pass-token-claims-in-http-headers)
* [Caddyfile Shortcuts](#caddyfile-shortcuts)
* [User Identity](#user-identity)

<!-- end-markdown-toc -->

## Ask Questions

Please ask questions and I will help you!

## Overview

With Caddy v2 modules (aka plugins), there is a shift in how one builds a plugin.
If a plugin is being used in multiple parts of a configuration, e.g. in different
routes, each part of the configuration initializes (provisions and validates) a
new instance of the plugin.

For example, this authorization plugin may be used to protect multiple routes.
It means that each of the routes will get its own instance of the plugin.

**How does configuration in one part affects other parts?**

* By default, a single instance of a plugin inherits "default" context.
* All instances of the plugin in an authorization context (e.g. "default"
  authorization context) inherit settings from the **primary** instance in
  the authorization context.
* There is only one **primary** instance in an authorization context.
* A plugin MUST have a **primary** instance in an authorization context.
* If an instance is not a **primary** instance, and a particular configuration
  property is not being set, then the instance inherits the property from the
  **primary** instance.

**What happens when a plugin does not have access list**

* If an instance of a plugin does not have an access list, it inherits the
  configuration from the **primary** instance in its authorization context.
* If a **primary** instance does not have an access list, the instances without
  an access list allow access for the holders of **anonymous** and **guest**
  claims.

## Limitations

Currently, the plugin implements limited set of features. As such the following
is still under development:

* `strip_token`
* `pass_claims`
* `token_types`: `HS` and `RS` algos are supported at the moment

[:arrow_up: Back to Top](#table-of-contents)

## Plugin Users

### Getting Started

#### JSON Configuration

This repository contains a sample configuration (see `assets/conf/config.json`).

My application is a reverse proxy for Prometheus and Alertmanager instances.
I want to allow access to the instances to the holders of **anonymous** and **guest**
claims.

The Alertmanager route is as follows. The instance of the plugin is NOT
a **primary** instance. The configuration is only an access list.

Since the context is not specified, this instance is in "default" authorization
context.

```json
            {
              "handle": [
                {
                  "handler": "authentication",
                  "providers": {
                    "jwt": {
                      "access_list": [
                        {
                          "action": "allow",
                          "claim": "roles",
                          "values": [
                            "anonymous",
                            "guest",
                            "admin"
                          ]
                        }
                      ]
                    }
                  }
                },
                {
                  "body": "alertmanager",
                  "handler": "static_response",
                  "status_code": 200
                }
              ],
              "match": [
                {
                  "path": [
                    "/alertmanager"
                  ]
                }
              ],
              "terminal": true
            },
```

Next, notice that Prometheus route the the **primary** in its authorization
context. It has the default setting for the context.

```json
            {
              "handle": [
                {
                  "handler": "authentication",
                  "providers": {
                    "jwt": {
                      "primary": true,
                      "token_name": "access_token",
                      "token_secret": "383aca9a-1c39-4d7a-b4d8-67ba4718dd3f",
                      "auth_url_path": "/auth",
                      "access_list": [
                        {
                          "action": "allow",
                          "claim": "roles",
                          "values": [
                            "anonymous",
                            "guest",
                            "admin"
                          ]
                        }
                      ],
                      "strip_token": false,
                      "pass_claims": false,
                      "token_types": [
                        "HS256",
                        "HS384",
                        "HS512"
                      ],
                      "token_sources": [
                        "header",
                        "cookie",
                        "query"
                      ]
                    }
                  }
                },
                {
                  "body": "prometheus",
                  "handler": "static_response",
                  "status_code": 200
                }
              ],
              "match": [
                {
                  "path": [
                    "/prometheus"
                  ]
                }
              ],
              "terminal": true
            },
```

The `primary` indicates that the instance is the primary instance in its
authorization context.

The `token_sources` configures where the plugin looks for an authorization
token. By default, it looks in Authorization header, cookies, and query
parameters.

The following `Caddyfile` directive instructs the plugin to search for
`Authorization: Bearer <JWT_TOKEN>` header and authorize the found token:

```
    jwt {
      option validate_bearer_header
    }
```

Test it with the following `curl` command:

```
curl --insecure -H "Authorization: Bearer JWT_TOKEN" -v https://localhost:8443/myapp
```

The `token_name` indicates the name of the token in the `token_sources`. By
default, it allows `jwt_access_token` and `access_token`.

The `token_secret` is the password for symmetric algorithms. If the secret
is not provided in the configuration, it can be passed via environment
variable `JWT_TOKEN_SECRET`.

The `auth_url_path` is the URL a user gets redirected to when a token is
invalid.

The `access_list` is the series of entries defining how to authorize claims.
In the above example, the plugin authorizes access for the holders of "roles"
claim where values are any of the following: "anonymous", "guest", "admin".

[:arrow_up: Back to Top](#table-of-contents)

#### Caddyfile

The following `Caddyfile` configuration mirrors closely the above JSON
configuration. 

```
{
  http_port 8080
  https_port 8443
  debug
}

localhost:8443 {
  route /prometheus* {
    jwt {
      primary yes
      trusted_tokens {
        static_secret {
          token_name access_token
          token_secret 383aca9a-1c39-4d7a-b4d8-67ba4718dd3f
        }
      }
      auth_url /auth
      allow roles anonymous guest admin
    }
    respond * "prometheus" 200
  }

  route /alertmanager* {
    jwt
    respond * "alertmanager" 200
  }

  route /auth* {
    respond * "auth portal" 200
  }

  route /version* {
    respond * "1.0.0" 200
  }

  route {
    redir https://{hostport}/auth 302
  }
}
```

Please note that the `jwt` directive instucts the instance of the
plugin to inherit all of its properties from the `primary` instance.
This greatly simplifies the configuration.

```
route /alertmanager* {
  jwt
  respond * "alertmanager" 200
}
```

[:arrow_up: Back to Top](#table-of-contents)

## Verification with RSA Public Keys

The following Caddyfile configuration has two different trusted
token backends:

* `static_secret`: based on shared secret, i.e. `cdcdc37a-6c65-4e43-b48a-8d047643d9df`
* `public_key`: validates key ID `Hz789bc303f0db` with the RSA Public Key in
 `/etc/gatekeeper/auth/jwt/verify_key.pem`


```
  route /prometheus* {
    jwt {
      primary yes
      trusted_tokens {
        static_secret {
          token_name access_token
          token_secret cdcdc37a-6c65-4e43-b48a-8d047643d9df
        }
        public_key {
          token_name access_token
          token_rsa_file Hz789bc303f0db /etc/gatekeeper/auth/jwt/verify_key.pem
        }
      }
```

The `verify_key.pem` is generated with the following command:

```bash
openssl genrsa -out /etc/gatekeeper/auth/jwt/sign_key.pem 2048
openssl rsa -in /etc/gatekeeper/auth/jwt/sign_key.pem -pubout -out /etc/gatekeeper/auth/jwt/verify_key.pem
```

The content of `verify_key.pem` follows:

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAphJPa8M0D/iY/I6kAs7K
4M30kPfurFEwpJe4zd9h9E/iuWbqpHCx+sQqAG8xJawddG6WupZiWRY3+44hw7nH
srH7XY2Dv/6igo1WU6U0PjHQ0SRSKGkGb3x4iwHx8IMsUQ44iDZYugxrjf5xkthc
6MNwqqcTuHLJtgEqSPETiqZgbcRHEWtqPb/LuQl3hLscokO7e5Yw0LQibtnZt4UR
Wb3z9CrzP8yS2Ibf8vbhiVhzYWSkXOiwsA0X5sBdNZbg8AkkqgyVe2FtCPBPdW6/
KOj8geX+P2Wms6msOZIRk7FqpKfEiK//arjumEsVF34S7GPavynLmyLfC4j9DcFI
PQIDAQAB
-----END PUBLIC KEY-----
```

[:arrow_up: Back to Top](#table-of-contents)

## Auto-Redirect URL

Consider the following configuration snippet. When the JWT plugin detects
unauthenticated user, it forwards the user to `https://auth.example.com`.

```
https://chat.example.com {
  jwt {
    auth_url https://auth.example.com/auth
  }
}
```

By default, the plugin adds the `redirect_url` parameter in URL query
pointing back to the page where the plugin detected unauthenticated user.
It signals an authenticator to redirect where to redirect the user upon
successful authentication.

If you would like to disable the addition of `redirect_url`, please
add `disable auth_redirect_query`:

```
https://chat.example.com {
  jwt {
    auth_url https://auth.example.com/auth
    disable auth_redirect_query
  }
}
```

[:arrow_up: Back to Top](#table-of-contents)

## Plugin Developers

This section of the documentation targets a plugin developer who wants to issue
JWT tokens as part of their plugin.

Please see [caddy-auth-portal](https://github.com/greenpau/caddy-auth-portal/blob/0bc10a3de90f63d44a6617ccbd284c2d23f73e39/pkg/backends/local/backend.go#L26)
for an example how to issue JWT tokens.

First, a developer would need to create `TokenProviderConfig` object via
`NewTokenProviderConfig()`.

```
tokenProvider := jwt.NewTokenProviderConfig()
```

Second, set the `TokenProviderConfig`
[properties](https://github.com/greenpau/caddy-auth-portal/blob/0bc10a3de90f63d44a6617ccbd284c2d23f73e39/pkg/backends/local/backend.go#L274-L297), e.g.:

* `TokenName`
* `TokenOrigin`
* `TokenLifetime`

Next, create a claim:

```go
    claims := &jwt.UserClaims{}
    claims.Subject = username
    claims.Email = username
    claims.Name = "Smith, John"
    claims.Roles = append(claims.Roles, "anonymous")
    claims.Roles = append(claims.Roles, "guest")
    claims.Origin = tokenProvider.TokenOrigin
    claims.ExpiresAt = time.Now().Add(time.Duration(tokenProvider.TokenLifetime) * time.Second).Unix()
```

Finally, having created claims, the developer can create a token string:

```go
userToken, err := claims.GetToken("HS512", []byte(m.TokenProvider.TokenSecret))
```

[:arrow_up: Back to Top](#table-of-contents)

## Role-based Access Control and Access Lists

### Sources of Role Information

By default, the plugin finds role information in the following token fields:

* `roles`
* `role`
* `group`
* `groups`
* `app_metadata` - `authorization` - `roles`
* `realm_access` - `roles`

In the below example, the use has a single role, i.e. `anonymous`.

```json
{
  "exp": 1596031874,
  "sub": "jsmith",
  "name": "Smith, John",
  "email": "jsmith@gmail.com",
  "roles": [
    "anonymous"
  ],
  "origin": "localhost"
}
```

Additionally, the token validation component of the plugin recognized that roles
may be in other parts of a token, e.g. `app_metadata - authorization - roles`:

```json
{
  "app_metadata": {
    "authorization": {
      "roles": ["admin", "editor"]
    }
  }
}
```

Additionally, `realm_access` - `roles`:

```json
{
  "realm_access": {
    "roles": ["admin", "editor"]
  }
}
```

References:

* [Auth0 Docs - App Metadata](https://auth0.com/docs/users/concepts/overview-user-metadata)
* [Netlify - Role-based access control with JWT - External providers](https://docs.netlify.com/visitor-access/role-based-access-control/#external-providers)

### Anonymous Role

By default, if the plugin does not find role information in JWT token, then
automatically treats the token having the following two roles:

* `anonymous`
* `guest`

For example, it happens when:
* `roles` and `app_metadata` are not present in a token
* `app_metadata` does not contain `authorization`

[:arrow_up: Back to Top](#table-of-contents)

### Granting Access with Access Lists

The authorization in the context of Caddy v2 is being processed by
an authentication handler, e.g. this plugin. The following snippet
is a configuration of one instance of the plugin (handler).

```json
{
  "handler": "authentication",
  "providers": {
    "jwt": {
      "access_list": [
        {
          "action": "allow",
          "claim": "roles",
          "values": [
            "anonymous",
            "guest",
            "admin"
          ]
        }
      ]
    }
  }
}
```

The `access_list` data structure contains a list of entries.

Each of the entries must have the following fields:
* `action`: `allow` or `deny`
* `claim`: currently the only allowed value is `roles`. The future plan for this
  field is the introduction of regular expressions to match various token fields
* `value`: it could be the name of a role or `*` or `any` for any value. The
  future plan for this field is the introduction of regular expressions to match
  role names

By default, if a plugin instance is primary and `access_list` key does not exist
in its configuration, the instance creates a default "allow" entry. The entry
grants access to `anonymous` and `guest` roles.

If there an entry with a matching claim and the action associated with the entry
is `deny`, then the claim is not allowed. This deny takes precedence over any
other matching `allow`.

The "catch-all" action is `deny`.

[:arrow_up: Back to Top](#table-of-contents)

### Default Allow ACL

If `jwt` configuration contains the following directive, then
The "catch-all" action is `allow`.

```
jwt {
  default allow
}
```

[:arrow_up: Back to Top](#table-of-contents)

### HTTP Method and Path in ACLs

The `jwt` plugin allows specifying HTTP method and path in access lists.

For example, the following configuration allows JWT token holders of
roles `anonymous` or `guest` to access the route, except for:
* POST to any endpoint
* GET to `/internal/dashboard` endpoint


```
route /* {
  jwt {
    deny roles anonymous guest with method get /internal/dashboard
    deny roles anonymous guest with method post
    allow roles anonymous guest
  }
  respond * "OK" 200
}
```

[:arrow_up: Back to Top](#table-of-contents)

### Forbidden Access

By default, `caddyauth.Authenticator` plugins should not set header or payload of the
response. However, caddy, by default, responds with 401 (instead of 403),
because `caddyauth.Authenticator` does not distinguish between authorization (403)
and authentication (401).

The plugin's default behaviour is responding with `403 Forbidden`.

However, one could use the `forbidden` Caddyfile directive to redirect users
to a custom 403 page.

```
jwt {
  # forbidden <path>
  forbidden /custom_403.html
}
```

[:arrow_up: Back to Top](#table-of-contents)

## Path-Based Access Lists

There are application that specify ACL in its own body, e.g.

```
{
  "iat": 1532093588,
  "jti": "705b6f50-8c21-11e8-9bcb-595326422d60",
  "sub": "jamie",
  "exp": "1532179987",
  "role": "users",
  "acl": {
    "paths": {
      "/*/users/**": {},
      "/*/conversations/**": {},
      "/*/sessions/**": {},
      "/*/devices/**": {},
      "/*/image/**": {},
      "/*/media/**": {},
      "/*/applications/**": {},
      "/*/push/**": {},
      "/*/knocking/**": {}
    }
  },
  "application_id": "aaaaaaaa-bbbb-cccc-dddd-0123456789ab"
}
```

To enable the validation of whether the requested path matches one
of the paths in JWT token claims, use the following Caddyfile
directive:

```
jwt {
   validate acl_path
}
```

The asterisk `*` signs get converted to the following regex patterns:

* `*`: `[a-zA-Z0-9_.~-]+`
* `**`: `[a-zA-Z0-9_/.~-]+`

## Pass Token Claims in HTTP Headers

To pass JWT token claims in HTTP headers to downstream plugins, use the
following Caddyfile directive:

```
jwt {
   ...
   enable claim headers
   ...
}
```

The downstream plugins would get the following `X-Token-` headers:

```
    "X-Token-Subject": "webadmin"
    "X-Token-User-Name": "Web Administrator"
    "X-Token-User-Email": "webadmin@localdomain.local"
    "X-Token-User-Roles": "superadmin guest anonymous"
```

[:arrow_up: Back to Top](#table-of-contents)

## Caddyfile Shortcuts

The following snippet in `jwt` Caddyfile:

```
    jwt {
      trusted_public_key 1 /etc/caddy/auth/jwt/jwt_publickey.pem
      ...
    }
```

Replaces the following:

```
    jwt {
      trusted_tokens {
        public_key {
          token_rsa_file 1 /etc/caddy/auth/jwt/jwt_publickey.pem
        }
      }
      ...
    }
```

[:arrow_up: Back to Top](#table-of-contents)

## User Identity

When the plugin successfully validates a JWT token, the plugin passes
the user identity identifier back to the Caddy server.

By default, the identity passed to Caddy is email address. However,
it could be changed with `user_identity` Caddyfile directive.

```
    jwt {
      user_identity id
      user_identity subject
      user_identity email
      ...
    }
```

If `email` is being set, but a JWT token does not contain an email address,
then the plugin uses `subject` for identity.
