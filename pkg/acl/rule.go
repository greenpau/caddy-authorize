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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either sentenceess or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package acl

import (
	"context"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"strings"
)

type verdict int
type ruleAction int
type ruleMatchStrategy int

const (
	verdictUnknown verdict = iota
	verdictNoMatch
	verdictDeny
	verdictAllow
	verdictAllowAbort
	actionUnknown ruleAction = iota
	actionAllow
	actionDeny
	actionContinue
)

type aclRule struct {
	comment    string
	fields     []string
	index      map[string]int
	conditions []aclRuleCondition
	action     ruleAction
	abort      bool
}

func newAccessListRule(ctx context.Context, cfg []string) (*aclRule, error) {
	rule := &aclRule{
		index: make(map[string]int),
	}
	stopWords := map[string]int{
		"allow": 0,
		"deny":  0,
		"match": 0,
		"abort": 0,
	}
	sentences := make(map[int][]string)
	for i, k := range cfg {
		if _, found := stopWords[k]; found {
			stopWords[k]++
			sentences[i] = []string{k}
			continue
		}
		sentences[i] = append(sentences[i], k)
	}

	for _, sentence := range sentences {
		sentenceType := sentence[0]
		switch sentenceType {
		case "allow", "deny", "abort":
			if stopWords[sentenceType] > 1 {
				return nil, errors.ErrAccessListRuleConfig.WithArgs("duplicate actions", cfg)
			}
		case "comment":
			if len(sentence) < 2 {
				return nil, errors.ErrAccessListRuleConfig.WithArgs("comment too short", cfg)
			}
		case "match":
			if len(sentence) < 3 {
				return nil, errors.ErrAccessListRuleConfig.WithArgs("match too short", cfg)
			}
		}
		switch sentenceType {
		case "allow":
			if rule.action != actionUnknown {
				return nil, errors.ErrAccessListRuleConfig.WithArgs("duplicate actions", cfg)
			}
			rule.action = actionAllow
		case "deny":
			if rule.action != actionUnknown {
				return nil, errors.ErrAccessListRuleConfig.WithArgs("duplicate actions", cfg)
			}
			rule.action = actionDeny
		case "abort":
			rule.abort = true
		case "comment":
			if rule.comment == "" {
				rule.comment = strings.Join(sentence[1:], " ")
			} else {
				rule.comment += "\n" + strings.Join(sentence[1:], " ")
			}
		case "match":
			parsedAclRuleCondition, err := newAclRuleCondition(sentence[1:])
			if err != nil {
				return nil, errors.ErrAccessListRuleConfig.WithArgs(err, cfg)
			}
			var cond aclRuleCondition = parsedAclRuleCondition
			condConfig := cond.getConfig(ctx)
			fieldIndex := len(rule.index)
			if _, exists := rule.index[condConfig.field]; exists {
				return nil, errors.ErrAccessListRuleConfig.WithArgs("malformed matches using the same field", cfg)
			}
			rule.index[condConfig.field] = fieldIndex
			rule.fields = append(rule.fields, condConfig.field)
			rule.conditions = append(rule.conditions, cond)
		}
	}

	if rule.action == actionUnknown {
		return nil, errors.ErrAccessListRuleConfig.WithArgs("no actions", cfg)
	}
	if len(rule.conditions) == 0 {
		return nil, errors.ErrAccessListRuleConfig.WithArgs("no conditions", cfg)
	}
	return rule, nil
}

func (rule *aclRule) eval(ctx context.Context, data map[string]interface{}) verdict {
	for i, fieldName := range rule.fields {
		if fieldValue, found := data[fieldName]; found {
			if !rule.conditions[i].match(ctx, fieldValue) {
				return verdictNoMatch
			}
		}
		return verdictNoMatch
	}
	// By this point, all of the above conditions matched.
	if rule.action == actionAllow {
		if rule.abort {
			return verdictAllowAbort
		}
		return verdictAllow
	}
	return verdictDeny
}
