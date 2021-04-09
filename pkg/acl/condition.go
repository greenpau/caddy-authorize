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
		"aud":    dataTypeListStr,
		"scopes": dataTypeListStr,
		"org":    dataTypeListStr,
		"jti":    dataTypeStr,
		"iss":    dataTypeStr,
		"sub":    dataTypeStr,
		"addr":   dataTypeStr,
	}
)

const (
	dataTypeUnknown dataType = iota
	dataTypeListStr
	dataTypeStr
)

const (
	fieldMatchUnknown fieldMatchStrategy = iota
	fieldMatchExact
	fieldMatchPartial
	fieldMatchPrefix
	fieldMatchSuffix
	fieldMatchRegex
	fieldMatchAlways
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
			if exp.value == v {
				return true
			}
		}
	}
	return false
}

func (c *ruleListStrCondPartialMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, exp := range c.exprs {
		for _, v := range values.([]string) {
			if strings.Contains(exp.value, v) {
				return true
			}
		}
	}
	return false
}

func (c *ruleListStrCondPrefixMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, exp := range c.exprs {
		for _, v := range values.([]string) {
			if strings.HasPrefix(exp.value, v) {
				return true
			}
		}
	}
	return false
}

func (c *ruleListStrCondSuffixMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, exp := range c.exprs {
		for _, v := range values.([]string) {
			if strings.HasSuffix(exp.value, v) {
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
		if c.expr.value == v {
			return true
		}
	}
	return false
}

func (c *ruleStrCondPartialMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, v := range values.([]string) {
		if strings.Contains(c.expr.value, v) {
			return true
		}
	}
	return false
}

func (c *ruleStrCondPrefixMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, v := range values.([]string) {
		if strings.HasPrefix(c.expr.value, v) {
			return true
		}
	}
	return false
}

func (c *ruleStrCondSuffixMatchListStrInput) match(ctx context.Context, values interface{}) bool {
	for _, v := range values.([]string) {
		if strings.HasSuffix(c.expr.value, v) {
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
		if exp.value == v.(string) {
			return true
		}
	}
	return false
}

func (c *ruleListStrCondPartialMatchStrInput) match(ctx context.Context, v interface{}) bool {
	for _, exp := range c.exprs {
		if strings.Contains(exp.value, v.(string)) {
			return true
		}
	}
	return false
}

func (c *ruleListStrCondPrefixMatchStrInput) match(ctx context.Context, v interface{}) bool {
	for _, exp := range c.exprs {
		if strings.HasPrefix(exp.value, v.(string)) {
			return true
		}
	}
	return false
}

func (c *ruleListStrCondSuffixMatchStrInput) match(ctx context.Context, v interface{}) bool {
	for _, exp := range c.exprs {
		if strings.HasSuffix(exp.value, v.(string)) {
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
	if c.expr.value == v.(string) {
		return true
	}
	return false
}

func (c *ruleStrCondPartialMatchStrInput) match(ctx context.Context, v interface{}) bool {
	if strings.Contains(c.expr.value, v.(string)) {
		return true
	}
	return false
}

func (c *ruleStrCondPrefixMatchStrInput) match(ctx context.Context, v interface{}) bool {
	if strings.HasPrefix(c.expr.value, v.(string)) {
		return true
	}
	return false
}

func (c *ruleStrCondSuffixMatchStrInput) match(ctx context.Context, v interface{}) bool {
	if strings.HasSuffix(c.expr.value, v.(string)) {
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

func newAclRuleCondition(cond []string) (aclRuleCondition, error) {
	var matchStrategy fieldMatchStrategy
	var condDataType dataType
	matchMode := cond[0]
	switch matchMode {

	case "exact":
		matchStrategy = fieldMatchExact
		cond = cond[1:]

	case "partial":
		matchStrategy = fieldMatchPartial
		cond = cond[1:]

	case "prefix":
		matchStrategy = fieldMatchPrefix
		cond = cond[1:]

	case "suffix":
		matchStrategy = fieldMatchSuffix
		cond = cond[1:]

	case "regex":
		matchStrategy = fieldMatchRegex
		cond = cond[1:]

	case "always":
		matchStrategy = fieldMatchAlways
		cond = cond[1:]

	default:
		matchStrategy = fieldMatchExact
	}
	fieldName := cond[0]
	inputDataType, exists := inputDataTypes[fieldName]
	if !exists {
		return nil, fmt.Errorf("unsupported field: %s", fieldName)
	}
	cond = cond[1:]
	switch len(cond) {
	case 0:
		return nil, fmt.Errorf("field %s condition has no values", fieldName)
	case 1:
		condDataType = dataTypeStr
	default:
		condDataType = dataTypeListStr
	}

	values := make([]string, len(cond))
	copy(values, cond)

	switch {

	case matchStrategy == fieldMatchExact && condDataType == dataTypeListStr && inputDataType == dataTypeListStr:
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
	case matchStrategy == fieldMatchExact && condDataType == dataTypeStr && inputDataType == dataTypeListStr:
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
	case matchStrategy == fieldMatchExact && condDataType == dataTypeListStr && inputDataType == dataTypeStr:
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
	case matchStrategy == fieldMatchExact && condDataType == dataTypeStr && inputDataType == dataTypeStr:
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
	case matchStrategy == fieldMatchPartial && condDataType == dataTypeListStr && inputDataType == dataTypeListStr:
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
	case matchStrategy == fieldMatchPartial && condDataType == dataTypeStr && inputDataType == dataTypeListStr:
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
	case matchStrategy == fieldMatchPartial && condDataType == dataTypeListStr && inputDataType == dataTypeStr:
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
	case matchStrategy == fieldMatchPartial && condDataType == dataTypeStr && inputDataType == dataTypeStr:
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
	case matchStrategy == fieldMatchPrefix && condDataType == dataTypeListStr && inputDataType == dataTypeListStr:
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
	case matchStrategy == fieldMatchPrefix && condDataType == dataTypeStr && inputDataType == dataTypeListStr:
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
	case matchStrategy == fieldMatchPrefix && condDataType == dataTypeListStr && inputDataType == dataTypeStr:
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
	case matchStrategy == fieldMatchPrefix && condDataType == dataTypeStr && inputDataType == dataTypeStr:
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
	case matchStrategy == fieldMatchSuffix && condDataType == dataTypeListStr && inputDataType == dataTypeListStr:
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
	case matchStrategy == fieldMatchSuffix && condDataType == dataTypeStr && inputDataType == dataTypeListStr:
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
	case matchStrategy == fieldMatchSuffix && condDataType == dataTypeListStr && inputDataType == dataTypeStr:
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
	case matchStrategy == fieldMatchSuffix && condDataType == dataTypeStr && inputDataType == dataTypeStr:
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
	case matchStrategy == fieldMatchRegex && condDataType == dataTypeListStr && inputDataType == dataTypeListStr:
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
			if re, err := regexp.Compile(val); err != nil {
				return nil, err
			} else {
				c.exprs = append(c.exprs, re)
			}
		}
		return c, nil
	case matchStrategy == fieldMatchRegex && condDataType == dataTypeStr && inputDataType == dataTypeListStr:
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
		if re, err := regexp.Compile(values[0]); err != nil {
			return nil, err
		} else {
			c.expr = re
		}
		return c, nil
	case matchStrategy == fieldMatchRegex && condDataType == dataTypeListStr && inputDataType == dataTypeStr:
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
			if re, err := regexp.Compile(val); err != nil {
				return nil, err
			} else {
				c.exprs = append(c.exprs, re)
			}
		}
		return c, nil
	case matchStrategy == fieldMatchRegex && condDataType == dataTypeStr && inputDataType == dataTypeStr:
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
		if re, err := regexp.Compile(values[0]); err != nil {
			return nil, err
		} else {
			c.expr = re
		}
		return c, nil
	case matchStrategy == fieldMatchAlways && condDataType == dataTypeListStr && inputDataType == dataTypeListStr:
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
	case matchStrategy == fieldMatchAlways && condDataType == dataTypeStr && inputDataType == dataTypeListStr:
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
	case matchStrategy == fieldMatchAlways && condDataType == dataTypeListStr && inputDataType == dataTypeStr:
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
	case matchStrategy == fieldMatchAlways && condDataType == dataTypeStr && inputDataType == dataTypeStr:
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
	return nil, fmt.Errorf("malformed")
}
