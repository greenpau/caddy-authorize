package jwt

import (
	"github.com/google/uuid"
	"math/rand"
	"strings"
)

const tokenLifetime = 900

// TokenProviderConfig represent JWT token provider configuration.
type TokenProviderConfig struct {
	TokenName   string `json:"token_name,omitempty"`
	TokenSecret string `json:"token_secret,omitempty"`
	TokenIssuer string `json:"token_issuer,omitempty"`
	// The expiration time of a token in seconds
	TokenLifetime int `json:"token_lifetime,omitempty"`
}

// NewTokenProviderConfig returns and instance of TokenProviderConfig.
func NewTokenProviderConfig() *TokenProviderConfig {
	c := &TokenProviderConfig{}
	return c
}

// SetDefaults sets default values for TokenProviderConfig.
func (c *TokenProviderConfig) SetDefaults() {
	if c.TokenName == "" {
		c.TokenName = uuid.New().String()
	}
	if c.TokenSecret == "" {
		c.TokenSecret = uuid.New().String()
		c.TokenSecret = c.TokenSecret + uuid.New().String()
		c.TokenSecret = strings.Replace(c.TokenSecret, "-", "", -1)
		c.TokenSecret = c.TokenSecret[rand.Intn(16):]
	}
	if c.TokenIssuer == "" {
		c.TokenIssuer = "localhost"
	}
	if c.TokenLifetime == 0 {
		c.TokenLifetime = tokenLifetime
	}
}
