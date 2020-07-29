package jwt

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	jwtlib "github.com/dgrijalva/jwt-go"
)

// Validator Errors
const (
	ErrNoBackends       strError = "no token backends available"
	ErrExpiredToken     strError = "expired token"
	ErrNoAccessList     strError = "user role is valid, but denied by default deny on empty access list"
	ErrAccessNotAllowed strError = "user role is valid, but not allowed by access list"
	ErrNoParsedClaims   strError = "failed to extract claims"
	ErrNoTokenFound     strError = "no token found"

	ErrInvalidParsedClaims strError = "failed to extract claims: %s"
	ErrInvalidSecret       strError = "secret key backend error: %s"
	ErrInvalid             strError = "%v"
)

const (
	tokenSourceHeader = "header"
	tokenSourceCookie = "cookie"
	tokenSourceQuery  = "query"
)

var tokenSources = map[string]byte{
	tokenSourceHeader: 0, // the value is the order they are in...
	tokenSourceCookie: 1,
	tokenSourceQuery:  2,
}

var allTokenSources []string

func init() { // set the default token_sources up
	allTokenSources = make([]string, len(tokenSources))
	for k, v := range tokenSources {
		allTokenSources[int(v)] = k
	}
}

var defaultTokenNames = []string{"access_token", "jwt_access_token"}

// TokenValidator validates tokens in http requests.
type TokenValidator struct {
	CommonTokenConfig
	AuthorizationHeaders map[string]struct{}
	Cookies              map[string]struct{}
	QueryParameters      map[string]struct{}
	Cache                *TokenCache
	AccessList           []*AccessListEntry
	TokenBackends        []TokenBackend
	TokenSources         []string
}

// NewTokenValidator returns an instance of TokenValidator
func NewTokenValidator() *TokenValidator {
	v := &TokenValidator{
		AuthorizationHeaders: make(map[string]struct{}),
		Cookies:              make(map[string]struct{}),
		QueryParameters:      make(map[string]struct{}),
	}

	for _, name := range defaultTokenNames {
		v.AuthorizationHeaders[name] = struct{}{}
		v.Cookies[name] = struct{}{}
		v.QueryParameters[name] = struct{}{}
	}

	v.Cache = NewTokenCache()
	return v
}

// SetTokenName sets the name of the token (i.e. <TokenName>=<JWT Token>)
// this overrites the default token names
func (v *TokenValidator) SetTokenName(name string) {
	v.TokenName = name
	v.AuthorizationHeaders = map[string]struct{}{name: struct{}{}}
	v.Cookies = map[string]struct{}{name: struct{}{}}
	v.QueryParameters = map[string]struct{}{name: struct{}{}}
}

// ConfigureTokenBackends configures available TokenBackend.
func (v *TokenValidator) ConfigureTokenBackends() error {
	v.TokenBackends = []TokenBackend{}
	if v.TokenSecret != "" {
		backend, err := NewSecretKeyTokenBackend(v.TokenSecret)
		if err != nil {
			return ErrInvalidSecret.WithArgs(err)
		}
		v.TokenBackends = append(v.TokenBackends, backend)
	}
	if len(v.TokenBackends) == 0 {
		return ErrNoBackends
	}
	return nil
}

// ClearAuthorizationHeaders clears source HTTP Authorization header.
func (v *TokenValidator) ClearAuthorizationHeaders() {
	v.AuthorizationHeaders = make(map[string]struct{})
}

// ClearCookies clears source HTTP cookies.
func (v *TokenValidator) ClearCookies() {
	v.Cookies = make(map[string]struct{})
}

// ClearQueryParameters clears source HTTP query parameters.
func (v *TokenValidator) ClearQueryParameters() {
	v.QueryParameters = make(map[string]struct{})
}

// ClearAllSources clears all sources of token data
func (v *TokenValidator) ClearAllSources() {
	v.ClearAuthorizationHeaders()
	v.ClearCookies()
	v.ClearQueryParameters()
}

// Authorize authorizes HTTP requests based on the presence and the
// content of the tokens in the request.
func (v *TokenValidator) Authorize(r *http.Request) (claims *UserClaims, valid bool, err error) {
	for _, sourceName := range v.TokenSources { // check the source in the order of the slice
		switch sourceName {
		case tokenSourceHeader:
			if claims, valid, err = v.AuthorizeAuthorizationHeader(r); valid || (err != nil && !errors.Is(err, ErrNoTokenFound)) {
				return claims, valid, err
			}
		case tokenSourceCookie:
			if claims, valid, err = v.AuthorizeCookies(r); valid || (err != nil && !errors.Is(err, ErrNoTokenFound)) {
				return claims, valid, err
			}
		case tokenSourceQuery:
			if claims, valid, err = v.AuthorizeQueryParameters(r); valid || (err != nil && !errors.Is(err, ErrNoTokenFound)) {
				return claims, valid, err
			}
		}
	}

	return claims, valid, err
}

// AuthorizeAuthorizationHeader authorizes HTTP requests based on the presence and the
// content of the tokens in HTTP Authorization header.
func (v *TokenValidator) AuthorizeAuthorizationHeader(r *http.Request) (u *UserClaims, ok bool, err error) {
	authzHeaderStr := r.Header.Get("Authorization")
	if authzHeaderStr != "" && len(v.AuthorizationHeaders) > 0 {
		if token, found := v.SearchAuthorizationHeader(authzHeaderStr); found {
			return v.ValidateToken(token)
		}
		err = ErrNoTokenFound
	}
	return u, ok, err
}

// AuthorizeCookies authorizes HTTP requests based on the presence and the
// content of the tokens in HTTP cookies.
func (v *TokenValidator) AuthorizeCookies(r *http.Request) (u *UserClaims, ok bool, err error) {
	// Second, check cookies
	cookies := r.Cookies()
	if len(cookies) > 0 && len(v.Cookies) > 0 {
		if token, found := v.SearchCookies(cookies); found {
			return v.ValidateToken(token)
		}
		err = ErrNoTokenFound
	}
	return u, ok, err
}

// AuthorizeQueryParameters authorizes HTTP requests based on the presence and the
// content of the tokens in HTTP query parameters.
func (v *TokenValidator) AuthorizeQueryParameters(r *http.Request) (u *UserClaims, ok bool, err error) {
	queryValues := r.URL.Query()
	if len(queryValues) > 0 && len(v.QueryParameters) > 0 {
		if token, found := v.SearchQueryValues(queryValues); found {
			return v.ValidateToken(token)
		}
		err = ErrNoTokenFound
	}
	return u, ok, err
}

// ValidateToken parses a token and returns claims, if valid.
func (v *TokenValidator) ValidateToken(s string) (*UserClaims, bool, error) {
	valid := false
	// First, check cached entries
	claims := v.Cache.Get(s)
	if claims != nil {
		if claims.ExpiresAt < time.Now().Unix() {
			v.Cache.Delete(s)
			return nil, false, ErrExpiredToken
		}
		valid = true
	}

	errorMessages := []string{}
	// If not valid, parse claims from a string.
	if !valid {
		for _, backend := range v.TokenBackends {
			token, err := jwtlib.Parse(s, backend.ProvideKey)
			if err != nil {
				errorMessages = append(errorMessages, err.Error())
				continue
			}
			if !token.Valid {
				continue
			}
			claims, err = ParseClaims(token)
			if err != nil {
				errorMessages = append(errorMessages, err.Error())
				continue
			}
			if claims == nil {
				errorMessages = append(errorMessages, "claims is nil")
				continue
			}
			valid = true
			break
		}
	}

	if valid {
		if len(v.AccessList) == 0 {
			return nil, false, ErrNoAccessList
		}
		aclAllowed := false
		for _, entry := range v.AccessList {
			claimAllowed, abortProcessing := entry.IsClaimAllowed(claims)
			if claimAllowed {
				aclAllowed = true
			}
			if abortProcessing {
				break

			}
		}
		if !aclAllowed {
			return nil, false, ErrAccessNotAllowed
		}
	}

	if !valid {
		return nil, false, ErrInvalid.WithArgs(errorMessages)
	}

	return claims, true, nil
}

// SearchAuthorizationHeader searches for tokens in the authorization header of
// HTTP requests.
func (v *TokenValidator) SearchAuthorizationHeader(s string) (string, bool) {
	if len(v.AuthorizationHeaders) == 0 || s == "" {
		return "", false
	}
	header := strings.Split(s, ",")
	for _, entry := range header {
		kv := strings.SplitN(entry, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.TrimSpace(kv[0])
		if _, exists := v.AuthorizationHeaders[k]; exists {
			return strings.TrimSpace(kv[1]), true
		}
	}
	return "", false
}

// SearchCookies searches for tokens in the cookies of HTTP requests.
func (v *TokenValidator) SearchCookies(cookies []*http.Cookie) (string, bool) {
	if len(cookies) == 0 || len(v.Cookies) == 0 {
		return "", false
	}
	for _, cookie := range cookies {
		if cookie == nil {
			continue
		}
		if _, exists := v.Cookies[cookie.Name]; exists {
			if len(cookie.Value) > 32 {
				token := strings.TrimSpace(cookie.Value)
				arr := strings.Split(token, " ")
				token = arr[0]
				return token, true
			}
		}
	}
	return "", false
}

// SearchQueryValues searches for tokens in the values of query parameters of
// HTTP requests.
func (v *TokenValidator) SearchQueryValues(params url.Values) (string, bool) {
	if len(v.QueryParameters) == 0 || len(params) == 0 {
		return "", false
	}

	for k := range v.QueryParameters {
		value := params.Get(k)
		if len(value) > 32 {
			return strings.TrimSpace(value), true
		}
	}

	return "", false
}

// ParseClaims extracts claims from a token.
func ParseClaims(token *jwtlib.Token) (*UserClaims, error) {
	claimMap := token.Claims.(jwtlib.MapClaims)
	claims, err := NewUserClaimsFromMap(claimMap)
	if err != nil {
		return nil, ErrInvalidParsedClaims.WithArgs(err)
	}
	if claims == nil {
		return nil, ErrNoParsedClaims
	}
	return claims, nil
}
