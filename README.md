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
* [Plugin Syntax](#plugin-syntax)
* [Getting Started](#getting-started)
* [Token Discovery](#token-discovery)
* [IP Address Filtering](#ip-address-filtering)
* [Token Verification](#token-verification)
  * [Verification with Shared Secret](#verification-with-shared-secret)
  * [Verification with RSA and ECDSA Keys](#verification-with-rsa-and-ecdsa-keys)
    * [Generate RSA Public Key](#generate-rsa-public-key)
    * [Generate ECDSA Public Key](#generate-ecdsa-public-key)
* [Auto-Redirect URL](#auto-redirect-url)
* [Javascript Redirect](#javascript-redirect)
* [Access Lists and Role-based Access Control (RBAC)](#access-lists-and-role-based-access-control-rbac)
  * [Sources of Role Information](#sources-of-role-information)
  * [Anonymous Role](#anonymous-role)
  * [Granting Access with Access Lists](#granting-access-with-access-lists)
    * [Comment](#comment)
    * [Conditions](#conditions)
    * [Actions](#actions)
    * [ACL Shortcuts](#acl-shortcuts)
    * [Primer](#primer)
  * [Default Allow ACL](#default-allow-acl)
  * [Forbidden Access](#forbidden-access)
* [Path-Based Access Lists](#path-based-access-lists)
* [Pass JWT Token Claims in HTTP Request Headers](#pass-jwt-token-claims-in-http-request-headers)
* [Strip JWT Token from HTTP Request](#strip-jwt-token-from-http-request)
* [User Identity](#user-identity)
* [Encryption](#encryption)

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
* If a **primary** instance does not have an access list, the instances plugin
  fails.

[:arrow_up: Back to Top](#table-of-contents)

## Plugin Syntax

```
jwt {
  primary <yes|no>
  context <default|name>

  crypto default token name <TOKEN_NAME>
  crypto default token lifetime <SECONDS>

  crypto key token name <TOKEN_NAME>
  crypto key <ID> token name <TOKEN_NAME>

  crypto key <verify|sign|sign-verify|auto> <SHARED_SECRET>
  crypto key <verify|sign|sign-verify|auto> from env <ENV_VAR_WITH_KEY>

  crypto key <ID> <verify|sign|sign-verify|auto> <SHARED_SECRET>
  crypto key <ID> <verify|sign|sign-verify|auto> from <directory|file> <PATH>

  crypto key <ID> <verify|sign|sign-verify|auto> from env <ENV_VAR_WITH_KEY>
  crypto key <ID> <verify|sign|sign-verify|auto> from env <ENV_VAR_NAME> as <directory|file>

  set auth url <path>
  set forbidden url <path>
  set token sources <value...>
  set user identity <claim_field>
  set redirect query parameter <value>
  set redirect status <3xx>

  disable auth redirect query
  disable auth redirect

  allow <field> <value...>
  allow <field> <value...> with <get|post|put|patch|delete> to <uri>
  allow <field> <value...> with <get|post|put|patch|delete>
  allow <field> <value...> to <uri>

  acl rule {
    comment <value>
    [exact|partial|prefix|suffix|regex|always] match <field> <value> ... <valueN>
    [exact|partial|prefix|suffix|regex|always] match method <http_method_name>
    [exact|partial|prefix|suffix|regex|always] match path <http_path_uri>
    <allow|deny> [stop] [counter] [log <error|warn|info|debug>]
  }

  validate path acl
  validate source address
  validate bearer header

  enable js redirect
  enable strip token

  inject headers with claims
}
```

[:arrow_up: Back to Top](#table-of-contents)

## Getting Started

This repository contains a sample configuration (see `assets/conf/Caddyfile`).

My application is a reverse proxy for Prometheus and Alertmanager instances.
I want to allow access to the instances to the holders of **anonymous** and **guest**
claims.

The Alertmanager route is as follows. The instance of the plugin is NOT
a **primary** instance. The configuration is only an access list.

Since the context is not specified, this instance is in "default" authorization
context.

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
      # omit crypto key directives for single server deployment
      # the plugin will auto-generate ECDSA key pair (ES512) and make
      # it available to portal plugin.
      crypto key verify 383aca9a-1c39-4d7a-b4d8-67ba4718dd3f
      crypto key token name access_token
      set auth url /auth
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

Next, notice that Prometheus route the the **primary** in its authorization
context. It has the default setting for the entire context, i.e. all the
routes with `jwt` directive.

The `primary` indicates that the instance is the primary instance in its
authorization context.

Please note that the `jwt` directive instucts the instance of the
plugin to inherit all of its properties from the `primary` instance.
This greatly simplifies the configuration.

```
route /alertmanager* {
  jwt
  respond * "alertmanager" 200
}
```

The `allow` and `deny` directives are the series of entries defining how to
authorize claims. In the above example, the plugin authorizes access
for the holders of "roles" claim where values are any of the
following: "anonymous", "guest", "admin".

[:arrow_up: Back to Top](#table-of-contents)

## Token Discovery

The `crypto key token name <NAME>` indicates the name of the token to be
searched in the token sources. By default, it is set to `jwt_access_token`
and `access_token`.

The `set token sources` configures where the plugin looks for an authorization
token. By default, it looks in Authorization header, cookies, and query
parameters. The way to change the order of the lookup or to limit the
search to a specific sources is using the following `Caddyfile` directive.

Limits the search of JWT tokens in cookies only.

```
    jwt {
      set token sources cookie
    }
```

Limits the search of JWT tokens cookies and query parameters.

```
    jwt {
      set token sources cookie query
    }
```

Reorders the default priority of the search of JWT tokens from "cookie",
"header", "query" to "header", "query", and "cookie".

```
    jwt {
      set token sources header query cookie
    }
```

Further, the following `Caddyfile` directive instructs the plugin to
search for `Authorization: Bearer <JWT_TOKEN>` header and authorize
the found token:

```
    jwt {
      validate bearer header
    }
```

Test it with the following `curl` command:

```
curl --insecure -H "Authorization: Bearer JWT_TOKEN" -v https://localhost:8443/myapp
```

[:arrow_up: Back to Top](#table-of-contents)

## IP Address Filtering

The following `Caddyfile` directive instructs the plugin to match the IP
address in a token with the source IP address of HTTP Request.

```
    jwt {
      validate source address
    }
```

[:arrow_up: Back to Top](#table-of-contents)

## Token Verification

Find the information about the various algorithms described below in
[RFC 7518](https://tools.ietf.org/html/rfc7518).

### Verification with Shared Secret

The shared secret methods are based on Hash-based Message Authentication Code
(HMAC) algorithm, where the hash is being computed using SHA256, SHA384, and
SHA512 hash functions.

The supported methods for the verification of token signatures are:

* `HS256`
* `HS384`
* `HS512`

The following Caddyfile directives set the default token verification key to
"shared" (symmetric) key with the value of `383aca9a-1c39-4d7a-b4d8-67ba4718dd3f`.
It also sets a custom token name. The plugin would search for tokens with
the `app_token` name.

```
  route /prometheus* {
    jwt {
      primary yes
      crypto key verify 383aca9a-1c39-4d7a-b4d8-67ba4718dd3f
      crypto key token name app_token
    }
  }
```

The syntax is:

```
crypto key verify <SHARED_SECRET>
crypto key token name <TOKEN_NAME>
```

Alternatively, the key could be set via environment variables. The
`from env APP_TOKEN` instructs the plugin to load the key from
`APP_TOKEN` environment variable.

```
  route /prometheus* {
    jwt {
      primary yes
      crypto key verify from env APP_TOKEN
      crypto key token name app_token
    }
  }
```

The syntax is:

```
crypto key verify from env <NAME>
crypto key token name <TOKEN_NAME>
```

Additionally, the key may have a key ID. It is otherwise known as `kid`.
It could be passed via right after the `crypto key` keywords.

```
  route /prometheus* {
    jwt {
      primary yes
      crypto key e5ZaB46bF27d verify 383aca9a-1c39-4d7a-b4d8-67ba4718dd3f
      crypto key e5ZaB46bF27d token name app_token
      crypto key 3bc4be49abf6 verify from env SECRET_TOKEN
      crypto key 3bc4be49abf6 token name secret_token
    }
  }
```

The syntax is:

```
crypto key <ID> verify <SHARED_SECRET>
crypto key <ID> verify from env <NAME>
crypto key <ID> token name <TOKEN_NAME>
```

[:arrow_up: Back to Top](#table-of-contents)

### Verification with RSA and ECDSA Keys

The RSA and ECDSA methods are based on asymmetric signature algorithms
defined in [RFC7518](https://tools.ietf.org/html/rfc7518).

The supported RSA methods are:

* `RS256`: RSASSA-PKCS1-v1_5 using SHA-256
* `RS384`
* `RS512`

The DSA are based on the Elliptic Curve Digital Signature Algorithm (ECDSA).
See [RFC7518 Section 3.4](https://tools.ietf.org/html/rfc7518#section-3.4)
for details.

The supported DSA methods are:

* `ES256`: ECDSA using P-256 and SHA-256 (SHA256withECDSA)
  - The Elliptic Curve has 256-bit integer prime.
* `ES384`: ECDSA using P-384 and SHA-384 (SHA384withECDSA)
  - The Elliptic Curve has 384-bit integer prime.
* `ES512`: ECDSA using P-521 and SHA-512 (SHA512withECDSA)
  - The Elliptic Curve has 512-bit integer prime.

The `P-256` curve (aka prime256v1) is being used in U2F and CBOR.

The verification of the tokens is being done by "public" RSA or ECDSA keys.
If the plugin finds a "private" key, it would extract "public" key from it
and that key would be used to verify tokens.

**NOTE**: The `verify` keyword is used when the keys provided are public keys.
Otherwise, user `sign-verify` or `auto`.

The following Caddyfile directives configure multiple token verification
keys.

1. The default key ID (aka kid 0) is defined when the key ID value is
   not provided. Loads the key from `/etc/gatekeeper/auth/jwt/verify_key1.pem` file.
1. The key ID `e5ZaB46bF27d`: loads from `/etc/gatekeeper/auth/jwt/verify_key2.pem`.
1. The key ID `3bc4be49abf6`: loads the key from the file stored in the `VERIFY_KEY_FILE`
   environment variable.
1. The key ID `pik3mfhsXR1B`: loads the keys from the directory stored in the
   environment variable `VERIFY_KEY_DIR`.

```
  route /prometheus* {
    jwt {
      primary yes
      crypto key verify from file /etc/gatekeeper/auth/jwt/verify_key1.pem
      crypto key e5ZaB46bF27d verify from file /etc/gatekeeper/auth/jwt/verify_key2.pem
      crypto key 3bc4be49abf6 verify from env VERIFY_KEY_FILE as file
      crypto key pik3mfhsXR1B verify from env VERIFY_KEY_DIR as directory
    }
  }
```

Additionally, there could be a directory with public PEM keys.

```
  route /prometheus* {
    jwt {
      primary yes
      crypto key e5ZaB46bF27d verify from directory /etc/gatekeeper/auth/jwt
      crypto key 3bc4be49abf6 verify from env VERIFY_KEY_DIR as directory
    }
  }
```

The syntax is:

```
crypto key <ID> verify from <directory|file> <PATH>
crypto key <ID> verify from env <NAME> as <directory|file|value>
```

#### Generate RSA Public Key

Th `verify_key1.pem` is RSA public key. It is generated with
the following commands:

```bash
openssl genrsa -out /etc/gatekeeper/auth/jwt/sign_key1.pem 2048
openssl rsa -in /etc/gatekeeper/auth/jwt/sign_key1.pem -pubout -out /etc/gatekeeper/auth/jwt/verify_key1.pem
```

The content of `verify_key1.pem` follows:

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

#### Generate ECDSA Public Key

The `verify_key1.pem` is generated with the following commands.

First, review the output of the following command to determine the
available Elliptic Curves.

```
$ openssl ecparam -list_curves
  secp224r1 : NIST/SECG curve over a 224 bit prime field
  secp256k1 : SECG curve over a 256 bit prime field
  secp384r1 : NIST/SECG curve over a 384 bit prime field
  secp521r1 : NIST/SECG curve over a 521 bit prime field
  prime256v1: X9.62/SECG curve over a 256 bit prime field
```

Next, generate `ES256` private and public key pair:

```bash
openssl ecparam -genkey -name prime256v1 -noout \
  -out /etc/gatekeeper/auth/jwt/sign_key2.pem
openssl ec -in /etc/gatekeeper/auth/jwt/sign_key2.pem -pubout \
  -out /etc/gatekeeper/auth/jwt/verify_key2.pem
```

The content of `verify_key2` follows:

```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwlCJyaA2uhZ29yhDkmsSm6nEageO
e0rB8fQM/g4WpLtz1AbPVZq9mjFHz390r7b2Dz6P/fNYqk5joikWVXrJ9g==
-----END PUBLIC KEY-----
```

For `ES384` use `-name secp384r1` argument.

For `ES512` use `-name secp521r1` argument.

[:arrow_up: Back to Top](#table-of-contents)

## Auto-Redirect URL

Consider the following configuration snippet. When the JWT plugin detects
unauthenticated user, it forwards the user to `https://auth.example.com`.

```
https://chat.example.com {
  jwt {
    set auth url https://auth.example.com/auth
  }
}
```

By default, the plugin adds the `redirect_url` parameter in URL query
pointing back to the page where the plugin detected unauthenticated user.
It signals an authenticator to redirect where to redirect the user upon
successful authentication.

If you would like to disable the addition of `redirect_url`, please
add `disable auth redirect query`:

```
https://chat.example.com {
  jwt {
    set auth url https://auth.example.com/auth
    disable auth redirect query
  }
}
```

If you would like to change the parameter name, e.g. from `redirect_url`
to `referer_url`, use the `set redirect query parameter` Caddyfile directive.

```
https://chat.example.com {
  jwt {
    set redirect query parameter referer_url
  }
}
```

The following Caddyfile directive changes the status code (default: `302`) for
the redirects.

```
https://chat.example.com {
  jwt {
    set redirect status 307
  }
}
```

If `jwt` configuration contains the following directive, then the redirect
is disabled and the request is refused with a HTTP `401 Unauthorized` error.

```
jwt {
  disable auth redirect
}
```

Importantly, if the plugin finds expired token, it attempts to extract the
token's issuer value. Then, it checks whether the value starts with `http`.
If it is, then the `set auth url` will be overwritten with the issuer's
web address.

[:arrow_up: Back to Top](#table-of-contents)

## Javascript Redirect

The following directive enables Javascript-based redirect. This is useful when
the URI path contains pound (`#`) sign.

```
jwt {
  enable js redirect
}
```

[:arrow_up: Back to Top](#table-of-contents)

## Access Lists and Role-based Access Control (RBAC)

The `allow` and `deny` directives are the series of entries defining how to
authorize claims. In the above example, the plugin authorizes access for the holders of "roles"
claim where values are any of the following: "anonymous", "guest", "admin".

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

Access list rule consists of 3 sections:

* Comment
* Conditions
* Actions

The rule has the following syntax:

```
acl rule {
  comment
  conditions
  action
}
```

For example:

```
acl rule {
  comment Allow viewer and editor access, log, count, and stop processing
  match roles viewer editor
  allow stop counter log debug
}
```

#### Comment

The comment section is a string to identify a rule.

The section is a single statement.

#### Conditions

The conditions section consists of one or more statements matching the fields
of a token.

There are the types of conditions:

1. match the value of a particular token field, e.g. `roles`
2. match the HTTP method, e.g. GET, POST, etc.
3. match the HTTP URI path, e.g. `/api`

The condition syntax follows:

```
[exact|partial|prefix|suffix|regex|always] match <field> <value> ... <valueN>
[exact|partial|prefix|suffix|regex|always] match method <http_method_name>
[exact|partial|prefix|suffix|regex|always] match path <http_path_uri>
```

The special use case is the value of `any` with `always` keyword. If provided,
it matches any value in a token field. It is synonymous to the field being
present. For example, the following condition match when a token has `org`
field. The value of the field is not being checked

```
always match org any
```

The following conditions match when a token has `roles` field with the values
of either `viewer` or `editor` and has `org` field with the value of `nyc`.

```
match roles viewer editor
match org nyc
```

The following conditions match when a token has `roles` field with the values
of either `viewer` or `editor` and `org` field begins with `ny`.

```
match roles viewer editor
prefix match org ny
```

[:arrow_up: Back to Top](#table-of-contents)

#### Actions

The actions section is a single line instructing how to deal with a token
which matches the conditions.

The potential values for actions follow. Please note the first keyword
could be `allow` or `deny`.

```
allow
allow counter
allow counter log <error|warn|info|debug>
allow log <error|warn|info|debug>
allow log <error|warn|info|debug> tag <value>
allow stop
allow stop counter
allow stop counter log <error|warn|info|debug>
allow stop log <error|warn|info|debug>
allow any
allow any counter
allow any counter log <error|warn|info|debug>
allow any log <error|warn|info|debug>
allow any stop
allow any stop counter
allow any stop counter log <error|warn|info|debug>
allow any stop log <error|warn|info|debug>
```

By default the ACL rule hits are not being logged or counted.

The `log <error|warn|info|debug>` keyword enables the logging of rule hits.
If the log level is not being set, it defaults to `info`.

The `tag` keyword instructs the plugin to add a tag to the log output.

The `counter` keyword enables the counting of hits. The counters could be
exposed with prometheus exporter.

The `stop` keyword instructs the plugin to stop processing ACL rules after
the processing the one with the `stop` keyword.

The `any` keyword instructs the plugin to trigger actions when any of the
conditions match. By default, all the conditions must match to trigger
actions.

[:arrow_up: Back to Top](#table-of-contents)

#### ACL Shortcuts

Here are the patterns of one-liner allowed for use:

```
allow roles viewer editor with method get /internal/dashboard
allow roles viewer editor with method post
deny roles anonymous guest with method get /internal/dashboard
deny roles anonymous guest with method post
allow roles anonymous guest
allow audience https://localhost/ https://example.com/
```

[:arrow_up: Back to Top](#table-of-contents)

#### Primer

In this example, the user logging via Facebook Login would get role `user`
added to his/her roles. The `acl rule` directives specify matches and actions.

```
localhost, 127.0.0.1 {
  route /auth* {
    authp {
      backends {
        github_oauth2_backend {
          method oauth2
          realm github
          provider github
          client_id Iv1.foobar
          client_secret barfoo
          scopes user
        }
      }
      ui {
        links {
          "My Identity" "/auth/whoami" icon "las la-star"
          "My Settings" /auth/settings icon "las la-cog"
          "Guests" /guest/
          "Users" /app/
          "Administrators" /admin/
        }
      }
      transform user {
        exact match sub 123456789
        exact match origin facebook
        action add role user
      }
      enable source ip tracking
    }
  }

  route /prometheus* {
    jwt {
      primary yes
      allow roles authp/admin authp/user authp/guest
      allow roles admin user guest
      validate bearer header
      set auth url /auth
      inject headers with claims
    }
    respond * "prometheus" 200
  }

  route /guest* {
    jwt {
      acl rule {
        comment allow guests only
        match role guest
        allow stop log error
      }
      acl rule {
        comment default deny
        always match iss any
        deny log error
      }
    }
    respond * "my app - guests only" 200
  }

  route /app* {
    jwt {
      acl rule {
        match role user admin
        allow stop log error
      }
      acl rule {
        always match iss any
        deny log error
      }
    }
    respond * "my app - standard users and admins" 200
  }

  route /admin* {
    jwt {
      acl rule {
        match role admin
        allow stop log error
      }
    }
    respond * "my app - admins only" 200
  }

  route /version* {
    respond * "1.0.0" 200
  }

  route {
    # trace tag="default"
    redir https://{hostport}/auth/login 302
  }
}
```

The log messages would look like this:

```
ERROR   http.authentication.providers.jwt       acl rule hit    {"action": "deny", "tag": "rule1", "user": {"addr":"10.0.2.2","iss":"https://localhost:8443/auth/oauth2/facebook/authorization-code-callback","jti":"yrQcSolE6SZAPeY38szaNQbtUtfyrj0HmfEq8hvL","name":"Paul Greenberg","origin":"facebook","roles":["user","authp/guest"],"sub":"10158919854597422"}}
```

### Default Allow ACL

If `jwt` configuration contains the following directive, then the "catch-all"
action is `allow`.

```
jwt {
  acl default allow
}
```

[:arrow_up: Back to Top](#table-of-contents)

### Forbidden Access

By default, `caddyauth.Authenticator` plugins should not set header or payload of the
response. However, caddy, by default, responds with 401 (instead of 403),
because `caddyauth.Authenticator` does not distinguish between authorization (403)
and authentication (401).

The plugin's default behaviour is responding with `403 Forbidden`.

However, one could use the `set forbidden url` Caddyfile directive to redirect
users to a custom 403 page.

```
jwt {
  set forbidden url /custom_403.html
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
   validate path acl
}
```

The asterisk `*` signs get converted to the following regex patterns:

* `*`: `[a-zA-Z0-9_.~-]+`
* `**`: `[a-zA-Z0-9_/.~-]+`

## Pass JWT Token Claims in HTTP Request Headers

To pass JWT token claims in HTTP headers to downstream plugins, use the
following Caddyfile directive:

```
jwt {
   ...
   inject headers with claims
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

## Strip JWT Token from HTTP Request

The following directive instructs the plugin to remove the found
token from a request.

```
jwt {
   ...
   enable strip token
   ...
}
```

[:arrow_up: Back to Top](#table-of-contents)

## User Identity

When the plugin successfully validates a JWT token, the plugin passes
the user identity identifier back to the Caddy server.

By default, the identity passed to Caddy is email address. However,
it could be changed with `set user identity` Caddyfile directive.

```
    jwt {
      set user identity id
      set user identity subject
      set user identity email
      ...
    }
```

If `email` is being set, but a JWT token does not contain an email address,
then the plugin uses `subject` for identity.

## Encryption

The following command generates ECDSA key with P-256 curve: 

```bash
openssl genpkey \
  -algorithm EC \
  -pkeyopt ec_param_enc:named_curve \
  -pkeyopt ec_paramgen_curve:P-256 | \
  openssl pkcs8 -topk8 -nocrypt -outform der > testdata/misckeys/test_4_es256_pri.pem
```
