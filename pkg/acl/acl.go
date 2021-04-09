// Copyright 2020 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package acl

import (
	// "github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"context"
	"strings"
)

// AccessList is a collection of access list rules.
type AccessList struct {
	config       []string
	rules        []*aclRule
	defaultAllow bool
}

// NewAccessList returns an instance of AccessList.
func NewAccessList() *AccessList {
	return &AccessList{
		rules: []*aclRule{},
	}
}

// SetDefaultAllowAction sets default allow for the AccessList,
// i.e. the AccessList fails open.
func (acl *AccessList) SetDefaultAllowAction() {
	acl.defaultAllow = true
}

func (acl *AccessList) AddRules(ctx context.Context, arr [][]string) error {
	for _, s := range arr {
		if err := acl.AddRule(ctx, s); err != nil {
			return err
		}
	}
	return nil
}

// Add adds a rule to AccessList.
func (acl *AccessList) AddRule(ctx context.Context, s []string) error {
	rule, err := newAccessListRule(ctx, s)
	if err != nil {
		return err
	}
	acl.config = append(acl.config, strings.Join(s, " "))
	acl.rules = append(acl.rules, rule)
	return nil
}

// Evaluate takes in client identity and metadata and returns an error when
// denied access.
func (acl *AccessList) Allow(ctx context.Context, data map[string]interface{}) bool {
	var grantAccess bool
	for _, rule := range acl.rules {
		v := rule.eval(ctx, data)
		switch v {
		case verdictAllowAbort:
			return true
		case verdictAllow:
			grantAccess = true
		case verdictDeny:
			return false
		}
	}
	if grantAccess || acl.defaultAllow {
		return true
	}
	return false
}
