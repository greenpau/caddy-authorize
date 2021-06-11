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
	"go.uber.org/zap"
)

// AccessList is a collection of access list rules.
type AccessList struct {
	config       []*RuleConfiguration
	rules        []aclRule
	logger       *zap.Logger
	defaultAllow bool
}

// NewAccessList returns an instance of AccessList.
func NewAccessList() *AccessList {
	return &AccessList{
		rules: []aclRule{},
	}
}

// GetRules returns configured ACL rules.
func (acl *AccessList) GetRules() []*RuleConfiguration {
	return acl.config
}

// SetDefaultAllowAction sets default allow for the AccessList,
// i.e. the AccessList fails open.
func (acl *AccessList) SetDefaultAllowAction() {
	acl.defaultAllow = true
}

// SetLogger adds a logger to AccessList.
func (acl *AccessList) SetLogger(logger *zap.Logger) {
	acl.logger = logger
}

// AddRules adds multiple rules to AccessList.
func (acl *AccessList) AddRules(ctx context.Context, cfgs []*RuleConfiguration) error {
	for _, cfg := range cfgs {
		if err := acl.AddRule(ctx, cfg); err != nil {
			return err
		}
	}
	return nil
}

// AddRule adds a rule to AccessList.
func (acl *AccessList) AddRule(ctx context.Context, cfg *RuleConfiguration) error {
	rule, err := newACLRule(ctx, len(acl.rules), cfg, acl.logger)
	if err != nil {
		return err
	}
	acl.config = append(acl.config, cfg)
	acl.rules = append(acl.rules, rule)
	return nil
}

// Allow takes in client identity and metadata and returns an error when
// denied access.
func (acl *AccessList) Allow(ctx context.Context, data map[string]interface{}) bool {
	var grantAccess bool
	for _, rule := range acl.rules {
		v := rule.eval(ctx, data)
		switch v {
		case ruleVerdictAllowStop:
			return true
		case ruleVerdictAllow:
			grantAccess = true
		case ruleVerdictDenyStop:
			return false
		case ruleVerdictDeny:
			return false
		}
	}
	if grantAccess || acl.defaultAllow {
		return true
	}
	return false
}

// GetFieldDataType return data type for a particular data field.
func GetFieldDataType(s string) (string, string) {
	k := s
	dt := dataTypeUnknown
	if v, exists := inputDataAliases[s]; exists {
		if vdt, exists := inputDataTypes[v]; exists {
			dt = vdt
			k = v
		}
	} else {
		if sdt, exists := inputDataTypes[s]; exists {
			dt = sdt
		}
	}
	switch dt {
	case dataTypeListStr:
		return k, "list_str"
	case dataTypeStr:
		return k, "str"
	}
	return k, ""
}
