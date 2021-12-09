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

package acl

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

type dataType int
type fieldMatchStrategy int

var (
	inputDataTypes = map[string]dataType{
		"roles":  dataTypeListStr,
		"email":  dataTypeStr,
		"origin": dataTypeStr,
		"name":   dataTypeStr,
		"realm":  dataTypeStr,
		"aud":    dataTypeListStr,
		"scopes": dataTypeListStr,
		"org":    dataTypeListStr,
		"jti":    dataTypeStr,
		"iss":    dataTypeStr,
		"sub":    dataTypeStr,
		"addr":   dataTypeStr,
		"method": dataTypeStr,
		"path":   dataTypeStr,
	}

	inputDataAliases = map[string]string{
		"id":           "jti",
		"audience":     "aud",
		"expires":      "exp",
		"issued":       "iat",
		"issuer":       "iss",
		"subject":      "sub",
		"mail":         "email",
		"role":         "roles",
		"group":        "roles",
		"groups":       "roles",
		"scope":        "scopes",
		"organization": "org",
		"address":      "addr",
		"ip":           "addr",
		"ipv4":         "addr",
		"http_method":  "method",
		"http_path":    "path",
	}
)

const (
	dataTypeUnknown dataType = 0
	dataTypeListStr dataType = 1
	dataTypeStr     dataType = 2

	fieldMatchUnknown  fieldMatchStrategy = 0
	fieldMatchReserved fieldMatchStrategy = 1
	fieldMatchExact    fieldMatchStrategy = 2
	fieldMatchPartial  fieldMatchStrategy = 3
	fieldMatchPrefix   fieldMatchStrategy = 4
	fieldMatchSuffix   fieldMatchStrategy = 5
	fieldMatchRegex    fieldMatchStrategy = 6
	fieldMatchAlways   fieldMatchStrategy = 7
)

type field struct {
	name   string
	length int
}

type expr struct {
	value  string
	length int
}

type config struct {
	field         string
	matchStrategy fieldMatchStrategy
	values        []string
	regexEnabled  bool
	alwaysTrue    bool
	exprDataType  dataType
	inputDataType dataType
	conditionType string
}

type aclRuleCondition interface {
	match(context.Context, interface{}) bool
	getConfig(context.Context) *config
}

// ruleListStrCondExactMatchListStrInput matches a list of strings input against a
// list of strings where any of the input values match at least one value of the
// condition using exact match.
type ruleListStrCondExactMatchListStrInput struct {
	field  *field
	exprs  []*expr
	config *config
}

// ruleListStrCondPartialMatchListStrInput matches a list of strings input against
// a list of strings where any of the input values match at least one value of the
// condition using substring match.
type ruleListStrCondPartialMatchListStrInput struct {
	field  *field
	exprs  []*expr
	config *config
}

// ruleListStrCondPrefixMatchListStrInput matches a list of strings input against a
// list of strings where any of the input values match at least one value of the
// condition using string prefix match.
type ruleListStrCondPrefixMatchListStrInput struct {
	field  *field
	exprs  []*expr
	config *config
}

// ruleListStrCondSuffixMatchListStrInput matches a list of strings input against a
// list of strings where any of the input values match at least one value of the
// condition using string suffix match.
type ruleListStrCondSuffixMatchListStrInput struct {
	field  *field
	exprs  []*expr
	config *config
}

// ruleListStrCondRegexMatchListStrInput matches a list of strings input against a
// list of strings where any of the input values match at least one value of the
// condition using regular expressions match.
type ruleListStrCondRegexMatchListStrInput struct {
	field  *field
	exprs  []*regexp.Regexp
	config *config
}

// ruleListStrCondAlwaysMatchListStrInput matches a list of strings input against a
// list of strings where any of the input values match at least one value of the
// condition using always match.
type ruleListStrCondAlwaysMatchListStrInput struct {
	field  *field
	exprs  []*expr
	config *config
}

// ruleStrCondExactMatchListStrInput matches a list of strings input against a
// string condition using exact match.
type ruleStrCondExactMatchListStrInput struct {
	field  *field
	expr   *expr
	config *config
}

// ruleStrCondPartialMatchListStrInput matches a list of strings input against a
// string condition using substring match.
type ruleStrCondPartialMatchListStrInput struct {
	field  *field
	expr   *expr
	config *config
}

// ruleStrCondPrefixMatchListStrInput matches a list of strings input against a
// string condition using string prefix match.
type ruleStrCondPrefixMatchListStrInput struct {
	field  *field
	expr   *expr
	config *config
}

// ruleStrCondSuffixMatchListStrInput matches a list of strings input against a
// string condition using string suffix match.
type ruleStrCondSuffixMatchListStrInput struct {
	field  *field
	expr   *expr
	config *config
}

// ruleStrCondRegexMatchListStrInput matches a list of strings input against a
// string condition using regular expressions match.
type ruleStrCondRegexMatchListStrInput struct {
	field  *field
	expr   *regexp.Regexp
	config *config
}

// ruleStrCondAlwaysMatchListStrInput matches a list of strings input against a
// string condition using always match.
type ruleStrCondAlwaysMatchListStrInput struct {
	field  *field
	expr   *expr
	config *config
}

// ruleListStrCondExactMatchStrInput matches an input string against a list of
// strings where any of the input values match at least one value of the condition
// using exact match.
type ruleListStrCondExactMatchStrInput struct {
	field  *field
	exprs  []*expr
	config *config
}

// ruleListStrCondPartialMatchStrInput matches an input string against a list of
// strings where any of the input values match at least one value of the condition
// using substring match.
type ruleListStrCondPartialMatchStrInput struct {
	field  *field
	exprs  []*expr
	config *config
}

// ruleListStrCondPrefixMatchStrInput matches an input string against a list of
// strings where any of the input values match at least one value of the condition
// using string prefix match.
type ruleListStrCondPrefixMatchStrInput struct {
	field  *field
	exprs  []*expr
	config *config
}

// ruleListStrCondSuffixMatchStrInput matches an input string against a list of
// strings where any of the input values match at least one value of the condition
// using string suffix match.
type ruleListStrCondSuffixMatchStrInput struct {
	field  *field
	exprs  []*expr
	config *config
}

// ruleListStrCondRegexMatchStrInput matches an input string against a list of
// strings where any of the input values match at least one value of the condition
// using regular expressions match.
type ruleListStrCondRegexMatchStrInput struct {
	field  *field
	exprs  []*regexp.Regexp
	config *config
}

// ruleListStrCondAlwaysMatchStrInput matches an input string against a list of
// strings where any of the input values match at least one value of the condition
// using always match.
type ruleListStrCondAlwaysMatchStrInput struct {
	field  *field
	exprs  []*expr
	config *config
}

// ruleStrCondExactMatchStrInput matches an input string against a string condition
// using exact match.
type ruleStrCondExactMatchStrInput struct {
	field  *field
	expr   *expr
	config *config
}

// ruleStrCondPartialMatchStrInput matches an input string against a string
// condition using substring match.
type ruleStrCondPartialMatchStrInput struct {
	field  *field
	expr   *expr
	config *config
}

// ruleStrCondPrefixMatchStrInput matches an input string against a string
// condition using string prefix match.
type ruleStrCondPrefixMatchStrInput struct {
	field  *field
	expr   *expr
	config *config
}

// ruleStrCondSuffixMatchStrInput matches an input string against a string
// condition using string suffix match.
type ruleStrCondSuffixMatchStrInput struct {
	field  *field
	expr   *expr
	config *config
}

// ruleStrCondRegexMatchStrInput matches an input string against a string condition
// using regular expressions match.
type ruleStrCondRegexMatchStrInput struct {
	field  *field
	expr   *regexp.Regexp
	config *config
}

// ruleStrCondAlwaysMatchStrInput matches an input string against a string
// condition using always match.
type ruleStrCondAlwaysMatchStrInput struct {
	field  *field
	expr   *expr
	config *config
}

func (c *ruleListStrCondExactMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, exp := range c.exprs {
		for _, v := range values.([]string) {
			if v == exp.value {
				return true
			}
		}
	}
	return false
}

func (c *ruleListStrCondPartialMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, exp := range c.exprs {
		for _, v := range values.([]string) {
			if strings.Contains(v, exp.value) {
				return true
			}
		}
	}
	return false
}

func (c *ruleListStrCondPrefixMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, exp := range c.exprs {
		for _, v := range values.([]string) {
			if strings.HasPrefix(v, exp.value) {
				return true
			}
		}
	}
	return false
}

func (c *ruleListStrCondSuffixMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, exp := range c.exprs {
		for _, v := range values.([]string) {
			if strings.HasSuffix(v, exp.value) {
				return true
			}
		}
	}
	return false
}

func (c *ruleListStrCondRegexMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, exp := range c.exprs {
		for _, v := range values.([]string) {
			if exp.MatchString(v) {
				return true
			}
		}
	}
	return false
}

func (c *ruleListStrCondAlwaysMatchListStrInput) match(ctx context.Context, v interface{}) bool {
	return true
}

func (c *ruleStrCondExactMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, v := range values.([]string) {
		if v == c.expr.value {
			return true
		}
	}
	return false
}

func (c *ruleStrCondPartialMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, v := range values.([]string) {
		if strings.Contains(v, c.expr.value) {
			return true
		}
	}
	return false
}

func (c *ruleStrCondPrefixMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, v := range values.([]string) {
		if strings.HasPrefix(v, c.expr.value) {
			return true
		}
	}
	return false
}

func (c *ruleStrCondSuffixMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, v := range values.([]string) {
		if strings.HasSuffix(v, c.expr.value) {
			return true
		}
	}
	return false
}

func (c *ruleStrCondRegexMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, v := range values.([]string) {
		if c.expr.MatchString(v) {
			return true
		}
	}
	return false
}

func (c *ruleStrCondAlwaysMatchListStrInput) match(ctx context.Context, v interface{}) bool {
	return true
}

func (c *ruleListStrCondExactMatchStrInput) match(ctx context.Context, v interface{}) bool {
	for _, exp := range c.exprs {
		if v.(string) == exp.value {
			return true
		}
	}
	return false
}

func (c *ruleListStrCondPartialMatchStrInput) match(ctx context.Context, v interface{}) bool {
	for _, exp := range c.exprs {
		if strings.Contains(v.(string), exp.value) {
			return true
		}
	}
	return false
}

func (c *ruleListStrCondPrefixMatchStrInput) match(ctx context.Context, v interface{}) bool {
	for _, exp := range c.exprs {
		if strings.HasPrefix(v.(string), exp.value) {
			return true
		}
	}
	return false
}

func (c *ruleListStrCondSuffixMatchStrInput) match(ctx context.Context, v interface{}) bool {
	for _, exp := range c.exprs {
		if strings.HasSuffix(v.(string), exp.value) {
			return true
		}
	}
	return false
}

func (c *ruleListStrCondRegexMatchStrInput) match(ctx context.Context, v interface{}) bool {
	for _, exp := range c.exprs {
		if exp.MatchString(v.(string)) {
			return true
		}
	}
	return false
}

func (c *ruleListStrCondAlwaysMatchStrInput) match(ctx context.Context, v interface{}) bool {
	return true
}

func (c *ruleStrCondExactMatchStrInput) match(ctx context.Context, v interface{}) bool {
	if v.(string) == c.expr.value {
		return true
	}
	return false
}

func (c *ruleStrCondPartialMatchStrInput) match(ctx context.Context, v interface{}) bool {
	if strings.Contains(v.(string), c.expr.value) {
		return true
	}
	return false
}

func (c *ruleStrCondPrefixMatchStrInput) match(ctx context.Context, v interface{}) bool {
	if strings.HasPrefix(v.(string), c.expr.value) {
		return true
	}
	return false
}

func (c *ruleStrCondSuffixMatchStrInput) match(ctx context.Context, v interface{}) bool {
	if strings.HasSuffix(v.(string), c.expr.value) {
		return true
	}
	return false
}

func (c *ruleStrCondRegexMatchStrInput) match(ctx context.Context, v interface{}) bool {
	if c.expr.MatchString(v.(string)) {
		return true
	}
	return false
}

func (c *ruleStrCondAlwaysMatchStrInput) match(ctx context.Context, v interface{}) bool {
	return true
}

func (c *ruleListStrCondExactMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondPartialMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondPrefixMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondSuffixMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondRegexMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondAlwaysMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondExactMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondPartialMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondPrefixMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondSuffixMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondRegexMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondAlwaysMatchListStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondExactMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondPartialMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondPrefixMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondSuffixMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondRegexMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleListStrCondAlwaysMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondExactMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondPartialMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondPrefixMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondSuffixMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondRegexMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func (c *ruleStrCondAlwaysMatchStrInput) getConfig(ctx context.Context) *config {
	return c.config
}

func newACLRuleCondition(ctx context.Context, tokens []string) (aclRuleCondition, error) {
	var matchStrategy fieldMatchStrategy
	var condDataType, inputDataType dataType
	var fieldName string
	var values []string
	var matchFound, fieldFound bool
	condInput := strings.Join(tokens, " ")
	for _, s := range tokens {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !matchFound {
			switch s {
			case "match":
				matchFound = true
				if matchStrategy == fieldMatchUnknown {
					matchStrategy = fieldMatchExact
				}
			case "reserved":
				matchStrategy = fieldMatchReserved
			case "exact":
				matchStrategy = fieldMatchExact
			case "partial":
				matchStrategy = fieldMatchPartial
			case "prefix":
				matchStrategy = fieldMatchPrefix
			case "suffix":
				matchStrategy = fieldMatchSuffix
			case "regex":
				matchStrategy = fieldMatchRegex
			case "always":
				matchStrategy = fieldMatchAlways
			}
		} else {
			switch s {
			case "exact", "partial", "prefix", "suffix", "regex", "always":
				return nil, fmt.Errorf("invalid condition syntax, use of reserved %q keyword: %s", s, condInput)
			}
			if !fieldFound {
				fieldName = s
				if v, exists := inputDataAliases[s]; exists {
					fieldName = v
				}
				tp, exists := inputDataTypes[fieldName]
				if !exists {
					return nil, fmt.Errorf("invalid condition syntax, unsupported field: %s, condition: %s", s, condInput)
				}
				inputDataType = tp
				fieldFound = true
			} else {
				values = append(values, s)
			}
		}
	}
	switch {
	case !matchFound:
		return nil, fmt.Errorf("invalid condition syntax, match not found: %s", condInput)
	case !fieldFound:
		return nil, fmt.Errorf("invalid condition syntax, field name not found: %s", condInput)
	case len(values) == 0:
		return nil, fmt.Errorf("invalid condition syntax, not matching field values: %s", condInput)
	}

	if len(values) == 1 {
		condDataType = dataTypeStr
	} else {
		condDataType = dataTypeListStr
	}

	switch {

	case matchStrategy == fieldMatchExact && condDataType == dataTypeListStr && inputDataType == dataTypeListStr:
		// Match: Exact, Condition Type: ListStr, Input Type: ListStr
		c := &ruleListStrCondExactMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchExact,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondExactMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*expr{}
		for _, val := range values {
			c.exprs = append(c.exprs, &expr{
				value: val,
			})
		}
		return c, nil
	case matchStrategy == fieldMatchPartial && condDataType == dataTypeListStr && inputDataType == dataTypeListStr:
		// Match: Partial, Condition Type: ListStr, Input Type: ListStr
		c := &ruleListStrCondPartialMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchPartial,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondPartialMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*expr{}
		for _, val := range values {
			c.exprs = append(c.exprs, &expr{
				value: val,
			})
		}
		return c, nil
	case matchStrategy == fieldMatchPrefix && condDataType == dataTypeListStr && inputDataType == dataTypeListStr:
		// Match: Prefix, Condition Type: ListStr, Input Type: ListStr
		c := &ruleListStrCondPrefixMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchPrefix,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondPrefixMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*expr{}
		for _, val := range values {
			c.exprs = append(c.exprs, &expr{
				value: val,
			})
		}
		return c, nil
	case matchStrategy == fieldMatchSuffix && condDataType == dataTypeListStr && inputDataType == dataTypeListStr:
		// Match: Suffix, Condition Type: ListStr, Input Type: ListStr
		c := &ruleListStrCondSuffixMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchSuffix,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondSuffixMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*expr{}
		for _, val := range values {
			c.exprs = append(c.exprs, &expr{
				value: val,
			})
		}
		return c, nil
	case matchStrategy == fieldMatchRegex && condDataType == dataTypeListStr && inputDataType == dataTypeListStr:
		// Match: Regex, Condition Type: ListStr, Input Type: ListStr
		c := &ruleListStrCondRegexMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchRegex,
				values:        values,
				regexEnabled:  true,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondRegexMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*regexp.Regexp{}
		for _, val := range values {
			re, err := regexp.Compile(val)
			if err != nil {
				return nil, err
			}
			c.exprs = append(c.exprs, re)
		}
		return c, nil
	case matchStrategy == fieldMatchAlways && condDataType == dataTypeListStr && inputDataType == dataTypeListStr:
		// Match: Always, Condition Type: ListStr, Input Type: ListStr
		c := &ruleListStrCondAlwaysMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchAlways,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    true,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondAlwaysMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*expr{}
		for _, val := range values {
			c.exprs = append(c.exprs, &expr{
				value: val,
			})
		}
		return c, nil
	case matchStrategy == fieldMatchExact && condDataType == dataTypeStr && inputDataType == dataTypeListStr:
		// Match: Exact, Condition Type: Str, Input Type: ListStr
		c := &ruleStrCondExactMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchExact,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondExactMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.expr = &expr{
			value: values[0],
		}
		return c, nil
	case matchStrategy == fieldMatchPartial && condDataType == dataTypeStr && inputDataType == dataTypeListStr:
		// Match: Partial, Condition Type: Str, Input Type: ListStr
		c := &ruleStrCondPartialMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchPartial,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondPartialMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.expr = &expr{
			value: values[0],
		}
		return c, nil
	case matchStrategy == fieldMatchPrefix && condDataType == dataTypeStr && inputDataType == dataTypeListStr:
		// Match: Prefix, Condition Type: Str, Input Type: ListStr
		c := &ruleStrCondPrefixMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchPrefix,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondPrefixMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.expr = &expr{
			value: values[0],
		}
		return c, nil
	case matchStrategy == fieldMatchSuffix && condDataType == dataTypeStr && inputDataType == dataTypeListStr:
		// Match: Suffix, Condition Type: Str, Input Type: ListStr
		c := &ruleStrCondSuffixMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchSuffix,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondSuffixMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.expr = &expr{
			value: values[0],
		}
		return c, nil
	case matchStrategy == fieldMatchRegex && condDataType == dataTypeStr && inputDataType == dataTypeListStr:
		// Match: Regex, Condition Type: Str, Input Type: ListStr
		c := &ruleStrCondRegexMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchRegex,
				values:        values,
				regexEnabled:  true,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondRegexMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		re, err := regexp.Compile(values[0])
		if err != nil {
			return nil, err
		}
		c.expr = re
		return c, nil
	case matchStrategy == fieldMatchAlways && condDataType == dataTypeStr && inputDataType == dataTypeListStr:
		// Match: Always, Condition Type: Str, Input Type: ListStr
		c := &ruleStrCondAlwaysMatchListStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchAlways,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    true,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondAlwaysMatchListStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.expr = &expr{
			value: values[0],
		}
		return c, nil
	case matchStrategy == fieldMatchExact && condDataType == dataTypeListStr && inputDataType == dataTypeStr:
		// Match: Exact, Condition Type: ListStr, Input Type: Str
		c := &ruleListStrCondExactMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchExact,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondExactMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*expr{}
		for _, val := range values {
			c.exprs = append(c.exprs, &expr{
				value: val,
			})
		}
		return c, nil
	case matchStrategy == fieldMatchPartial && condDataType == dataTypeListStr && inputDataType == dataTypeStr:
		// Match: Partial, Condition Type: ListStr, Input Type: Str
		c := &ruleListStrCondPartialMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchPartial,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondPartialMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*expr{}
		for _, val := range values {
			c.exprs = append(c.exprs, &expr{
				value: val,
			})
		}
		return c, nil
	case matchStrategy == fieldMatchPrefix && condDataType == dataTypeListStr && inputDataType == dataTypeStr:
		// Match: Prefix, Condition Type: ListStr, Input Type: Str
		c := &ruleListStrCondPrefixMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchPrefix,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondPrefixMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*expr{}
		for _, val := range values {
			c.exprs = append(c.exprs, &expr{
				value: val,
			})
		}
		return c, nil
	case matchStrategy == fieldMatchSuffix && condDataType == dataTypeListStr && inputDataType == dataTypeStr:
		// Match: Suffix, Condition Type: ListStr, Input Type: Str
		c := &ruleListStrCondSuffixMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchSuffix,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondSuffixMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*expr{}
		for _, val := range values {
			c.exprs = append(c.exprs, &expr{
				value: val,
			})
		}
		return c, nil
	case matchStrategy == fieldMatchRegex && condDataType == dataTypeListStr && inputDataType == dataTypeStr:
		// Match: Regex, Condition Type: ListStr, Input Type: Str
		c := &ruleListStrCondRegexMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchRegex,
				values:        values,
				regexEnabled:  true,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondRegexMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*regexp.Regexp{}
		for _, val := range values {
			re, err := regexp.Compile(val)
			if err != nil {
				return nil, err
			}
			c.exprs = append(c.exprs, re)
		}
		return c, nil
	case matchStrategy == fieldMatchAlways && condDataType == dataTypeListStr && inputDataType == dataTypeStr:
		// Match: Always, Condition Type: ListStr, Input Type: Str
		c := &ruleListStrCondAlwaysMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchAlways,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    true,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleListStrCondAlwaysMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.exprs = []*expr{}
		for _, val := range values {
			c.exprs = append(c.exprs, &expr{
				value: val,
			})
		}
		return c, nil
	case matchStrategy == fieldMatchExact && condDataType == dataTypeStr && inputDataType == dataTypeStr:
		// Match: Exact, Condition Type: Str, Input Type: Str
		c := &ruleStrCondExactMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchExact,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondExactMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.expr = &expr{
			value: values[0],
		}
		return c, nil
	case matchStrategy == fieldMatchPartial && condDataType == dataTypeStr && inputDataType == dataTypeStr:
		// Match: Partial, Condition Type: Str, Input Type: Str
		c := &ruleStrCondPartialMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchPartial,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondPartialMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.expr = &expr{
			value: values[0],
		}
		return c, nil
	case matchStrategy == fieldMatchPrefix && condDataType == dataTypeStr && inputDataType == dataTypeStr:
		// Match: Prefix, Condition Type: Str, Input Type: Str
		c := &ruleStrCondPrefixMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchPrefix,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondPrefixMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.expr = &expr{
			value: values[0],
		}
		return c, nil
	case matchStrategy == fieldMatchSuffix && condDataType == dataTypeStr && inputDataType == dataTypeStr:
		// Match: Suffix, Condition Type: Str, Input Type: Str
		c := &ruleStrCondSuffixMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchSuffix,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondSuffixMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.expr = &expr{
			value: values[0],
		}
		return c, nil
	case matchStrategy == fieldMatchRegex && condDataType == dataTypeStr && inputDataType == dataTypeStr:
		// Match: Regex, Condition Type: Str, Input Type: Str
		c := &ruleStrCondRegexMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchRegex,
				values:        values,
				regexEnabled:  true,
				alwaysTrue:    false,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondRegexMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		re, err := regexp.Compile(values[0])
		if err != nil {
			return nil, err
		}
		c.expr = re
		return c, nil
	case matchStrategy == fieldMatchAlways && condDataType == dataTypeStr && inputDataType == dataTypeStr:
		// Match: Always, Condition Type: Str, Input Type: Str
		c := &ruleStrCondAlwaysMatchStrInput{
			config: &config{
				field:         fieldName,
				matchStrategy: fieldMatchAlways,
				values:        values,
				regexEnabled:  false,
				alwaysTrue:    true,
				exprDataType:  condDataType,
				inputDataType: inputDataType,
				conditionType: `ruleStrCondAlwaysMatchStrInput`,
			},
			field: &field{
				name:   fieldName,
				length: len(fieldName),
			},
		}
		c.expr = &expr{
			value: values[0],
		}
		return c, nil

	}
	return nil, fmt.Errorf("invalid condition syntax: %s", condInput)
}

func getMatchStrategyName(s fieldMatchStrategy) string {
	switch s {
	case fieldMatchExact:
		return "fieldMatchExact"
	case fieldMatchPartial:
		return "fieldMatchPartial"
	case fieldMatchPrefix:
		return "fieldMatchPrefix"
	case fieldMatchSuffix:
		return "fieldMatchSuffix"
	case fieldMatchRegex:
		return "fieldMatchRegex"
	case fieldMatchAlways:
		return "fieldMatchAlways"
	case fieldMatchReserved:
		return "fieldMatchReserved"
	}
	return "fieldMatchUnknown"
}
func getDataTypeName(s dataType) string {
	switch s {
	case dataTypeListStr:
		return "dataTypeListStr"
	case dataTypeStr:
		return "dataTypeStr"
	}
	return "dataTypeUnknown"
}
