package jwt

import (
	"fmt"
	"strings"
)

// AccessListEntry represent an access list entry.
type AccessListEntry struct {
	Action string   `json:"action,omitempty"`
	Values []string `json:"values,omitempty"`
	Claim  string   `json:"claim,omitempty"`
}

// NewAccessListEntry return an instance of AccessListEntry.
func NewAccessListEntry() *AccessListEntry {
	return &AccessListEntry{}
}

// Validate checks access list entry compliance
func (acl *AccessListEntry) Validate() error {
	if acl.Action == "" {
		return fmt.Errorf("empty access list action")
	}
	if acl.Action != "allow" && acl.Action != "deny" {
		return fmt.Errorf("unsupported access list action: %s", acl.Action)
	}
	if acl.Claim == "" {
		return fmt.Errorf("empty access list claim")
	}
	if len(acl.Values) == 0 {
		return fmt.Errorf("no acl.Values")
	}
	return nil
}

// Allow sets action to allow in an access list entry.
func (acl *AccessListEntry) Allow() {
	acl.Action = "allow"
	return
}

// Deny sets action to deny in an access list entry.
func (acl *AccessListEntry) Deny() {
	acl.Action = "deny"
	return
}

// SetClaim sets claim value of an access list entry.
func (acl *AccessListEntry) SetClaim(s string) error {
	if s == "" {
		return fmt.Errorf("empty claim value")
	}
	acl.Claim = s
	return nil
}

// AddValue adds value to an access list entry.
func (acl *AccessListEntry) AddValue(s string) error {
	if s == "" {
		return fmt.Errorf("empty value")
	}
	acl.Values = append(acl.Values, s)
	return nil
}

// SetValue sets value to an access list entry.
func (acl *AccessListEntry) SetValue(arr []string) error {
	if len(arr) == 0 {
		return fmt.Errorf("empty value")
	}
	acl.Values = arr
	return nil
}

// GetAction returns access list entry action.
func (acl *AccessListEntry) GetAction() string {
	return acl.Action
}

// GetClaim returns access list entry claim name.
func (acl *AccessListEntry) GetClaim() string {
	return acl.Claim
}

// GetValues returns access list entry claim values.
func (acl *AccessListEntry) GetValues() string {
	return strings.Join(acl.Values, " ")
}
