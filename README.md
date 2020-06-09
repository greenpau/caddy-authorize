# caddy-auth-jwt

<a href="https://github.com/greenpau/caddy-auth-jwt/actions/" target="_blank"><img src="https://github.com/greenpau/caddy-auth-jwt/workflows/build/badge.svg?branch=master"></a>
<a href="https://pkg.go.dev/github.com/greenpau/caddy-auth-jwt" target="_blank"><img src="https://img.shields.io/badge/godoc-reference-blue.svg"></a>
<a href="https://caddy.community" target="_blank"><img src="https://img.shields.io/badge/community-forum-ff69b4.svg"></a>

JWT Authorization Plugin for [Caddy v2](https://github.com/caddyserver/caddy).

This work is inspired by [BTBurke/caddy-jwt](https://github.com/BTBurke/caddy-jwt).
Many thanks to @BTBurke and other contributors for the plugin

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
  authorization context) inherit settings from the **master** instance in
  the authorization context.
* There is only one **master** instance in an authorization context.
* A plugin MUST have a **master** instance in an authorization context.
* If an instance is not a **master** instance, and a particular configuration
  property is not being set, then the instance inherits the property from the
  **master** instance.

**What happens when a plugin does not have access list**

* If an instance of a plugin does not have an access list, it inherits the
  configuration from the **master** instance in its authorization context.
* If a **master** instance does not have an access list, the instances without
  an access list allow access for the holders of **anonymous** and **guest**
  claims.

## Limitations

Currently, the plugin implements limited set of features. As such the following
is still under development:

* `strip_token`
* `pass_claims`
* `token_types`: only HS algo at the moment.

## Plugin Users

### Getting Started

This repository contains a sample configuration (see `assets/conf/config.json`).

My application is a reverse proxy for Prometheus and Alertmanager instances.
I want to allow access to the instances to the holders of **anonymous** and **guest**
claims.

The Alertmanager route is as follows. The instance of the plugin is NOT
a **master** instance. The configuration is only an access list.

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

Next, notice that Prometheus route the the **master** in its authorization
context. It has the default setting for the context.

```json
            {
              "handle": [
                {
                  "handler": "authentication",
                  "providers": {
                    "jwt": {
                      "master": true,
                      "token_name": "access_token",
                      "token_secret": "383aca9a-1c39-4d7a-b4d8-67ba4718dd3f",
                      "token_issuer": "7a50e023-2c6e-4a5e-913e-23ecd0e2b940",
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

The `master` indicates that the instance is the master instance in its
authorization context.

The `token_sources` configures where the plugin looks for an authorization
token. By default, it looks in Authorization header, cookies, and query
parameters.

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

### Access List

TODO. Meanwhile, please open an issue.

## Plugin Developers

This section of the documentation targets a plugin developer who wants to issue
JWT tokens as part of their plugin 

TODO. Meanwhile, please open an issue.
