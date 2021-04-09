#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import argparse
import sys
import logging
import textwrap
import collections
from string import Template
from pprint import pformat
logging.basicConfig(stream=sys.stderr, level=logging.DEBUG,
                    format='[%(asctime)s] %(levelname)s %(name)s@%(lineno)d: %(message)s')
LOG = logging.getLogger()

FIELD_TYPES = collections.OrderedDict({
    'roles':  'ListStr',
    'email':  'Str',
    'origin': 'Str',
    'name':   'Str',
    'aud':    'ListStr',
    'scopes': 'ListStr',
    'org':    'ListStr',
    'jti':    'Str',
    'iss':    'Str',
    'sub':    'Str',
    'addr':   'Str',
})

HTTP_METHODS = ['POST', 'PUT', 'GET', 'PATCH',
                'DELETE', 'HEAD', 'CONNECT', 'OPTIONS', 'TRACE']

INPUTDATA = collections.OrderedDict({
    'ListStr': {
        'description': 'a list of strings input',
        'cmp': 'v',
    },
    'Str': {
        'description': 'an input string',
        'cmp': 'v.(string)',
    },
})

CONDS = collections.OrderedDict({
    'ListStr': {
        'description': 'against a list of strings',
        'attrs': {
            'default': [
                'field *field',
                'exprs []*expr',
                'config *config',
            ],
            'Regex': [
                'field *field',
                'exprs []*regexp.Regexp',
                'config *config',
            ],
        },
        'cmp': 'exp',
        'configure': {
            'default': [
                '''
                c.exprs = []*expr{}
                for _, val := range values {
                    c.exprs = append(c.exprs, &expr{
                        value: val,
                    })
                }
                ''',
            ],
            'Regex': [
                '''
                c.exprs = []*regexp.Regexp{}
                for _, val := range values {
                    if re, err := regexp.Compile(val); err != nil {
                        return nil, err
                    } else {
                        c.exprs = append(c.exprs, re)
                    }
                }
                ''',
            ],
        },
    },
    'Str': {
        'description': 'against a string condition',
        'attrs': {
            'default': [
                'field *field',
                'expr *expr',
                'config *config',
            ],
            'Regex': [
                'field *field',
                'expr *regexp.Regexp',
                'config *config',
            ],
        },
        'cmp': 'c.expr',
        'configure': {
            'default': [
                '''
                c.expr = &expr{
                    value: values[0],
                }''',
            ],
            'Regex': [
                '''
		if re, err := regexp.Compile(values[0]); err != nil {
                    return nil, err
                } else {
                    c.expr = re
                }''',
            ],
        },
    },
})

MATCHES = collections.OrderedDict({
    'Exact': {
        'description': 'exact',
        'expr': 'if %s == %s {',
    },
    'Partial': {
        'description': 'substring',
        'expr': 'if strings.Contains(%s, %s) {',
    },
    'Prefix': {
        'description': 'string prefix',
        'expr': 'if strings.HasPrefix(%s, %s) {',
    },
    'Suffix': {
        'description': 'string suffix',
        'expr': 'if strings.HasSuffix(%s, %s) {',
    },
    'Regex': {
        'description': 'regular expressions',
        'expr': 'if %s.MatchString(%s) {',
    },
    'Always': {
        'description': 'always',
    },
})


def makeCompare(condType, dataType, matchType):
    output = []
    exprFunc = MATCHES[matchType]['expr']
    dataKey = INPUTDATA[dataType]['cmp']
    condKey = CONDS[condType]['cmp']
    if matchType != 'Regex':
        condKey += '.value'
    cmpExpr = exprFunc % (condKey, dataKey)
    output.append(cmpExpr)
    output.append('return true')
    output.append('}')
    return output


def makeMatchFunction(t):
    ct = t['cond_data_type']
    it = t['input_data_type']
    mt = t['match_type']
    output = []
    if mt == 'Always':
        output.append('''
        func (c *%s) match(ctx context.Context, v interface{}) bool {
            return true
        }
        ''' % (t['name']))
        return output
    fn = 'func (c *%s) match(ctx context.Context, ' % (t['name'])
    if ct == 'Str' and it == 'Str':
        fn += 'v interface{}) bool {'
        output.append(fn)
        x = makeCompare(ct, it, mt)
        # LOG.debug('\n'.join(x))
        output.extend(x)
    elif ct == 'Str' and it == 'ListStr':
        fn += 'values interface{}) bool {'
        output.append(fn)
        output.append('''
        for _, v := range values.([]string) {
        ''')
        output.extend(makeCompare(ct, it, mt))
        output.append('}')
    elif ct == 'ListStr' and it == 'Str':
        fn += 'v interface{}) bool {'
        output.append(fn)
        output.append('for _, exp := range c.exprs {')
        output.extend(makeCompare(ct, it, mt))
        output.append('}')
    elif ct == 'ListStr' and it == 'ListStr':
        fn += 'values interface{}) bool {'
        output.append(fn)
        output.append('''
        for _, exp := range c.exprs {
            for _, v := range values.([]string) {
        ''')
        output.extend(makeCompare(ct, it, mt))
        output.append('}\n}')
    else:
        raise Exception(
            "bad condition: condition value type %s, input value type: %s" % (ct, it))

    output.append('''return false
    }
    ''')
    return output


def makeGetConfigFunction(t):
    output = []
    output.append('''
    func (c *%s) getConfig(ctx context.Context) *config {
        return c.config
    }
    ''' % (t['name']))

    return output


def getStructName(inputValueType, condValueType, matchType):
    return "rule%sCond%sMatch%sInput" % (condValueType, matchType, inputValueType)


def makeTestHeader():
    output = '''
    package acl

    import(
        "github.com/greenpau/caddy-auth-jwt/pkg/tests"
        "testing"
        "strings"
        "context"
    )
    '''
    return output


def makeTestNewAclRuleConditionTemplate():
    output = '''
    func TestAclRuleConditions(t *testing.T) {
        var testcases = []struct {
            name      string
            condition string
            want      map[string]interface{}
            shouldErr bool
            err       error
        }{
            %s
        }
        for _, tc := range testcases {
            t.Run(tc.name, func(t *testing.T) {
                var cond aclRuleCondition
                parsedAclRuleCondition, err := newAclRuleCondition(strings.Split(tc.condition, " "))
                if tests.EvalErr(t, err, tc.condition, tc.shouldErr, tc.err) {
                    return
                }
                cond = parsedAclRuleCondition
                condConfig := cond.getConfig(context.Background())
                got := make(map[string]interface{})
                got["condition_type"] = condConfig.field
                got["condition_type"] = condConfig.conditionType
                tests.EvalObjects(t, "output", tc.want, got)
            })
        }
    }
    '''
    return output


def makeHeader():
    output = ['''
    package acl

    import(
        "fmt"
        "context"
        "regexp"
        "strings"
    )

    type dataType int
    type fieldMatchStrategy int

    var (
    ''']

    output.append('inputDataTypes = map[string]dataType{')
    for k in FIELD_TYPES.keys():
        output.append('"%s": dataType%s,' % (k, FIELD_TYPES[k]))
    output.append('}')

    output.append('''
    )

    const (
        dataTypeUnknown dataType = iota''')

    for k in CONDS.keys():
        output.append('    dataType%s' % (k))

    output.append('''
    )

    const (
        fieldMatchUnknown fieldMatchStrategy = iota''')

    for k in MATCHES.keys():
        output.append('    fieldMatch%s' % (k))

    output.append('''
    )

    type field struct {
        name string
        length int
    }

    type expr struct {
        value string
        length int
    }

    type config struct {
        field string
        matchStrategy fieldMatchStrategy
        values []string
        regexEnabled bool
        alwaysTrue bool
        exprDataType dataType
        inputDataType dataType
        conditionType string
    }

    type aclRuleCondition interface {
        match(context.Context, interface{}) bool
        getConfig(context.Context) *config
    }
    ''')
    return output


def makeNewAclRuleCondition(struct_name, match_type, cond_data_type, input_data_type):
    output = []
    case = 'case matchStrategy == fieldMatch%s' % (match_type)
    case += '&& condDataType == dataType%s' % (cond_data_type)
    case += '&& inputDataType == dataType%s:' % (input_data_type)
    output.append(case)

    regexEnabled = "false"
    if match_type == 'Regex':
        regexEnabled = "true"
    alwaysTrue = "false"
    if match_type == 'Always':
        alwaysTrue = "true"

    # Create the condition and config
    output.append('''
        c := &%s{
            config: &config{
                field: fieldName,
                matchStrategy: fieldMatch%s,
                values: values,
                regexEnabled: %s,
                alwaysTrue: %s,
                exprDataType: condDataType,
                inputDataType: inputDataType,
                conditionType: `%s`,
            },
            field: &field{
                name: fieldName,
                length: len(fieldName),
            },
        }''' % (struct_name, match_type, regexEnabled, alwaysTrue, struct_name))

    # Next, configure expressions.
    if cond_data_type in ['Str', 'ListStr']:
        if match_type in CONDS[cond_data_type]['configure']:
            output.extend(CONDS[cond_data_type]['configure'][match_type])
        else:
            output.extend(CONDS[cond_data_type]['configure']['default'])
    else:
        raise Exception("unsupported condition data type: %s" %
                        (cond_data_type))

    output.append('''
        return c, nil
    ''')
    return output


def makeNewTypeFunction(type_structs):
    output = ['''
    func newAclRuleCondition(cond []string) (aclRuleCondition, error) {
        var matchStrategy fieldMatchStrategy
        var condDataType dataType
        matchMode := cond[0]
        switch matchMode {
    ''']
    for k in MATCHES.keys():
        output.append('''
            case "%s":
                matchStrategy = fieldMatch%s
                cond = cond[1:]
        ''' % (k.lower(), k))

    output.append('''
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
    ''')

    for k in MATCHES.keys():
        for t in type_structs:
            if k != t['match_type']:
                continue
            lines = makeNewAclRuleCondition(
                t['name'], k, t['cond_data_type'], t['input_data_type'])
            for line in lines:
                output.append(line.strip())

    output.append('''
        }
        return nil, fmt.Errorf("malformed")
    }
    ''')
    return output


def makeTypeStruct(t):
    output = []
    ct = t['cond_data_type']
    it = t['input_data_type']
    mt = t['match_type']
    description = "%s matches %s" % (
        t['name'], INPUTDATA[t['input_data_type']]['description'])
    description += " %s" % (CONDS[t['cond_data_type']]['description'])
    if 'List' in t['cond_data_type']:
        description += " where any of the input values match at least one value of the condition"
    description += " using %s match." % (
        MATCHES[t['match_type']]['description'])
    for line in textwrap.wrap(description, width=80):
        output.append("// " + line)
    output.append("type %s struct {" % (t['name']))

    ts_attrs = []
    if mt in CONDS[ct]['attrs']:
        ts_attrs = CONDS[ct]['attrs'][mt]
    else:
        ts_attrs = CONDS[ct]['attrs']['default']
    for ts_attr in ts_attrs:
        output.append("    %s" % (ts_attr))
    output.extend(['}', ''])
    return output


def generateTypeStructs(inputValueType, condValueType, matchType):
    type_structs = []
    for i in inputValueType:
        for j in condValueType:
            for k in matchType:
                t = {
                    "name": getStructName(i, j, k),
                    "input_data_type": i,
                    "cond_data_type": j,
                    "match_type": k,
                }
                type_structs.append(t)
    return type_structs


def getTestName(fieldName, inputValueType, condValueType, matchType):
    name = "match %s field" % (fieldName)
    name += " %s" % (INPUTDATA[inputValueType]['description']).lower()
    name += " %s" % (CONDS[condValueType]['description']).lower()
    if 'List' in condValueType:
        name += " match any"
    name += " with %s match" % (matchType.lower())
    return name


def generateTestCases(inputValueType, condValueType, matchType):
    output = []
    for i in inputValueType:
        for j in condValueType:
            for k in matchType:
                for m in FIELD_TYPES.keys():
                    if FIELD_TYPES[m] != j:
                        continue
                    t = {
                        "name": getTestName(m, i, j, k),
                        "struct_name": getStructName(i, j, k),
                        "input_data_type": i,
                        "cond_data_type": j,
                        "match_type": k.lower(),
                        "field_name": m,
                    }
                    output.append(t)
    return output


def generateCode():
    output = []
    inputValueType = INPUTDATA.keys()
    condValueType = CONDS.keys()
    matchType = MATCHES.keys()
    type_structs = generateTypeStructs(
        inputValueType, condValueType, matchType)
    output.extend(makeHeader())

    for t in type_structs:
        output.extend(makeTypeStruct(t))

    for t in type_structs:
        output.append('')
        for line in makeMatchFunction(t):
            output.append(line.strip())

    for t in type_structs:
        output.append('')
        for line in makeGetConfigFunction(t):
            output.append(line.strip())

    output.extend(makeNewTypeFunction(type_structs))
    return '\n'.join(output)


def makeTestNewAclRuleCondition(t):
    cdt = t['cond_data_type']
    match_type = t['match_type']
    name = '%s' % (t['name'])
    if cdt == 'ListStr':
        cdv = "barfoo foobar"
    elif cdt == 'Str':
        cdv = "foobar"
    else:
        raise Exception("unsupported condition data type: %s" % (cdt))

    tc = '''{
        name: "%s",
        condition: `%s %s`,
        want: map[string]interface{}{
            "condition_type": "%s",
            "field_name": "%s",
        },
    },
    ''' % (name, t['field_name'], cdv, t['struct_name'], t['field_name'])
    return tc


def generateTests():
    output = []
    inputValueType = INPUTDATA.keys()
    condValueType = CONDS.keys()
    matchType = MATCHES.keys()
    test_cases = generateTestCases(inputValueType, condValueType, matchType)
    # LOG.debug(pformat(test_cases, width=260))

    test_statements = []
    for t in test_cases:
        st = makeTestNewAclRuleCondition(t)
        test_statements.append(st)

    header = makeTestHeader()
    output.append(header)
    tmplAclRuleConditions = makeTestNewAclRuleConditionTemplate()
    output.append(tmplAclRuleConditions % (''.join(test_statements)))
    return '\n'.join(output)


def main():
    descr = str(os.path.basename(__file__))
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter, add_help=True, description=descr)
    main_group = parser.add_argument_group(None)
    main_group.add_argument('--code-output', metavar='FILE_PATH', dest='code_output', type=argparse.FileType('w'),
                            default=sys.stdout, help='Write code to output file (or stdout)')
    main_group.add_argument('--test-output', metavar='FILE_PATH', dest='test_output', type=argparse.FileType('w'),
                            help='Write tests to output file (or stdout)')
    args = parser.parse_args()

    # LOG.info(pformat(t))
    code = generateCode()
    tests = generateTests()

    args.code_output.write(code)
    args.test_output.write(tests)


if __name__ == '__main__':
    main()
