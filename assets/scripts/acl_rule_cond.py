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
        'keyword': 'exact',
    },
    'Partial': {
        'description': 'substring',
        'expr': 'if strings.Contains(%s, %s) {',
        'keyword': 'partial',
    },
    'Prefix': {
        'description': 'string prefix',
        'expr': 'if strings.HasPrefix(%s, %s) {',
        'keyword': 'prefix',
    },
    'Suffix': {
        'description': 'string suffix',
        'expr': 'if strings.HasSuffix(%s, %s) {',
        'keyword': 'suffix',
    },
    'Regex': {
        'description': 'regular expressions',
        'expr': 'if %s.MatchString(%s) {',
        'keyword': 'regex',
    },
    'Always': {
        'description': 'always',
        'keyword': 'always',
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
        "reflect"
        "testing"
        "strings"
        "context"
        "fmt"
    )
    '''
    return output


def makeTestNewAclRuleConditionTemplate():
    output = '''
    func TestNewAclRuleCondition(t *testing.T) {
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
                t.Logf(tc.name)
                t.Logf(tc.condition)
                var cond aclRuleCondition
                parsedAclRuleCondition, err := newAclRuleCondition(strings.Split(tc.condition, " "))
                if tests.EvalErr(t, err, tc.condition, tc.shouldErr, tc.err) {
                    return
                }
                cond = parsedAclRuleCondition
                condConfig := cond.getConfig(context.Background())
                got := make(map[string]interface{})
                got["field_name"] = condConfig.field
                // got["condition_type"] = condConfig.conditionType
                got["condition_type"] = reflect.TypeOf(cond).String()
                got["match_strategy"] = getMatchStrategyName(condConfig.matchStrategy)
                got["default_match_strategy"] = getMatchStrategyName(fieldMatchUnknown)
                got["regex_enabled"] = condConfig.regexEnabled
                got["always_true"] = condConfig.alwaysTrue
                got["expr_data_type"] = getDataTypeName(condConfig.exprDataType)
                got["input_data_type"] = getDataTypeName(condConfig.inputDataType)
                got["default_data_type"] = getDataTypeName(dataTypeUnknown)
                got["values"] = condConfig.values
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
        dataTypeUnknown dataType = 0''')

    for i, k in enumerate(CONDS.keys()):
        output.append('    dataType%s dataType = %d' % (k, i+1))

    output.append('''

        fieldMatchUnknown fieldMatchStrategy = 0''')

    for i, k in enumerate(MATCHES.keys()):
        output.append('    fieldMatch%s fieldMatchStrategy = %d' % (k, i+1))

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
    case += ' && condDataType == dataType%s' % (cond_data_type)
    case += ' && inputDataType == dataType%s:' % (input_data_type)
    output.append(case)
    output.append("// Match: %s, Condition Type: %s, Input Type: %s" %
                  (match_type, cond_data_type, input_data_type))

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


def makeGetMatchStrategyNameFunction():
    output = []
    fnCases = []
    for i, k in enumerate(MATCHES.keys()):
        fnCases.append('''case fieldMatch%s:
        return "fieldMatch%s"''' % (k, k))
    fn = '''
    func getMatchStrategyName(s fieldMatchStrategy) (string) {
        switch s {
        %s
        }
        return "fieldMatchUnknown"
    }
    ''' % ('\n'.join(fnCases))
    output.append(fn.strip())
    return output


def makeGetDataTypeNameFunction():
    output = []
    fnCases = []
    for i, k in enumerate(CONDS.keys()):
        fnCases.append('''case dataType%s:
        return "dataType%s"''' % (k, k))
    fn = '''
    func getDataTypeName(s dataType) (string) {
        switch s {
        %s
        }
        return "dataTypeUnknown"
    }
    ''' % ('\n'.join(fnCases))
    output.append(fn.strip())
    return output


def makeNewTypeFunction(type_structs):
    match_keys = []
    for k in MATCHES.keys():
        match_keys.append(k.lower())
    output = ['''
    func newAclRuleCondition(words []string) (aclRuleCondition, error) {
        var matchStrategy fieldMatchStrategy
        var condDataType, inputDataType dataType
        var fieldName string
        var values []string
        var matchFound, fieldFound bool
        condInput := strings.Join(words, " ")
        for _, s := range words {
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
                    }''']
    for k in MATCHES.keys():
        output.append('''
                case "%s":
                    matchStrategy = fieldMatch%s
        '''.strip() % (k.lower(), k))
    output.append('''}
            } else {
                switch s {
                case "''' + '", "'.join(match_keys) + '''":
                    return nil, fmt.Errorf("invalid condition syntax, use of reserved keyword: %s", condInput)
                }
                if !fieldFound {
                    if tp, exists := inputDataTypes[s]; !exists {
                        return nil, fmt.Errorf("invalid condition syntax, unsupported field: %s, condition: %s", s, condInput)
                    } else {
                        inputDataType = tp
                    }
                    fieldName = s
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
    ''')

    x = '''
    for t in type_structs:
        for k in MATCHES.keys():
            LOG.debug(t['name'] + ' ---- ' + k)
            LOG.debug(t['cond_data_type'])
            LOG.debug(t['input_data_type'])
            if k + "Match" not in t['name']:
                continue
            if "rule" + t['cond_data_type'] + "Cond" not in t['name']:
                continue
            if "Match" + t['input_data_type'] + "Input" not in t['name']:
                continue
            # if k.lower() != t['match_type'].lower():
            #    continue
            LOG.debug(t['name'] + ' ---- ' + k)
            lines = makeNewAclRuleCondition(
                t['name'], k, t['cond_data_type'], t['input_data_type'])
            for line in lines:
                output.append(line.strip())
    '''
    for t in type_structs:
        if t['match_type'] + "Match" not in t['name'] or "rule" + t['cond_data_type'] + "Cond" not in t['name'] or "Match" + t['input_data_type'] + "Input" not in t['name']:
            LOG.debug(t['name'])
            LOG.debug("  %s", t['cond_data_type'])
            LOG.debug("  %s", t['input_data_type'])
            LOG.debug("  %s", t['match_type'])
            raise Exception("Invalid struct")
            continue
        lines = makeNewAclRuleCondition(
            t['name'], t['match_type'], t['cond_data_type'], t['input_data_type'])
        for line in lines:
            output.append(line.strip())

    output.append('''
        }
        return nil, fmt.Errorf("invalid condition syntax: %s", condInput)
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


def generateTestCases():
    output = []
    for f in FIELD_TYPES.keys():
        for m in MATCHES.keys():
            for c in CONDS.keys():
                fieldDataType = FIELD_TYPES[f]
                for i in INPUTDATA.keys():
                    if i != fieldDataType:
                        # LOG.debug("field %s type %s vs. input value type %s",
                        #          f, fieldDataType, i)
                        continue
                    test_name = "%s match" % (MATCHES[m]['keyword'])
                    test_name += " %s" % (INPUTDATA[i]['description'])
                    test_name += " %s" % (CONDS[c]['description'])
                    test_name += " in %s field" % (f)
                    exp_struct_name = "rule%sCond%sMatch%sInput" % (c, m, i)
                    t = {
                        "name": test_name,
                        "struct_name": exp_struct_name,
                        "input_data_type": i,
                        "cond_data_type": c,
                        "match_type": m,
                        "match_keyword": MATCHES[m]['keyword'],
                        "field_name": f,
                    }
                    output.append(t)
                    if m != 'Exact':
                        continue
                    # define default use case (exact)
                    test_name = "default match"
                    test_name += " %s" % (INPUTDATA[i]['description'])
                    test_name += " %s" % (CONDS[c]['description'])
                    test_name += " in %s field" % (f)
                    exp_struct_name = "rule%sCond%sMatch%sInput" % (
                        c, "Exact", i)
                    td = {
                        "name": test_name,
                        "struct_name": exp_struct_name,
                        "input_data_type": i,
                        "cond_data_type": c,
                        "match_type": "Exact",
                        "match_keyword": "",
                        "field_name": f,
                    }
                    output.append(td)
    # raise Exception("XXXX")
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
    output.extend(makeGetMatchStrategyNameFunction())
    output.extend(makeGetDataTypeNameFunction())
    return '\n'.join(output)


def makeTestNewAclRuleCondition(t):
    output = []
    for status in ['success', 'error']:
        if status == 'success':
            if t['cond_data_type'] == 'ListStr':
                cdv = "barfoo foobar"
            elif t['cond_data_type'] == 'Str':
                cdv = "foobar"
            else:
                raise Exception("unsupported condition data type: %s" % (cdt))

            tc = '{'
            tc += '    name: "%s",\n' % (t['name'])
            tc += '    condition: `%s match %s %s`,\n' % (
                t['match_keyword'], t['field_name'], cdv)
            tc += '    want: map[string]interface{}{\n'
            tc += '        "condition_type": "*acl.%s",\n' % (t['struct_name'])
            tc += '        "field_name": "%s",\n' % (t['field_name'])
            # regex match
            if t['match_type'] == 'Regex':
                tc += '        "regex_enabled": true,\n'
            else:
                tc += '        "regex_enabled": false,\n'
            tc += '        "match_strategy": "fieldMatch%s",\n' % (
                t['match_type'])
            # always true match
            if t['match_type'] == 'Always':
                tc += '        "always_true": true,\n'
            else:
                tc += '        "always_true": false,\n'
            tc += '        "default_match_strategy": "fieldMatchUnknown",\n'
            tc += '        "default_data_type": "dataTypeUnknown",\n'
            tc += '        "expr_data_type": "dataType%s",\n' % (
                t["cond_data_type"])
            tc += '        "input_data_type": "dataType%s",\n' % (
                t["input_data_type"])

            tc += '        "values": []string{`' + \
                '`,`'.join(cdv.split(' ')) + '`},\n'

            tc += '    },\n'
            tc += '},\n'
            output.append(tc.strip())
            continue
        if t['match_keyword'] == 'regex':
            if t['cond_data_type'] == 'ListStr':
                cdv = "barfoo (foobar|raboff"
                errMsg = "error parsing regexp: missing closing ): `(foobar|raboff`"
            elif t['cond_data_type'] == 'Str':
                cdv = "foobar|raboff)"
                errMsg = "error parsing regexp: unexpected ): `foobar|raboff)`"
            else:
                raise Exception("unsupported condition data type: %s" % (cdt))
            tc = '''{
                name: "failed %s",
                condition: `%s match %s %s`,
                shouldErr: true,
                err: fmt.Errorf("%s"),
            },
            ''' % (t['name'], t['match_keyword'], t['field_name'], cdv, errMsg)
            output.append(tc.strip())
            continue

    return output


def makeTestNewAclRuleConditionCustomFailed():
    output = []
    test_cases = [
        {
            "name": "invalid condition syntax match not found",
            "condition": "exact",
            "error": 'fmt.Errorf("invalid condition syntax, match not found: exact")',
        },
        {
            "name": "invalid condition syntax field name not found",
            "condition": "exact match",
            "error": 'fmt.Errorf("invalid condition syntax, field name not found: exact match")',
        },
        {
            "name": "invalid condition syntax not matching field values",
            "condition": "exact match roles",
            "error": 'fmt.Errorf("invalid condition syntax, not matching field values: exact match roles")',
        },
        {
            "name": "invalid condition syntax use of reserved keyword",
            "condition": "exact match partial",
            "error": 'fmt.Errorf("invalid condition syntax, use of reserved keyword: exact match partial")',
        },
        {
            "name": "invalid condition syntax unsupported field",
            "condition": "exact match bootstrap yes",
            "error": 'fmt.Errorf("invalid condition syntax, unsupported field: bootstrap, condition: exact match bootstrap yes")',
        },
    ]
    for t in test_cases:
        tc = '''{
            name: "%s",
            condition: `%s`,
            shouldErr: true,
            err: %s,
        },
        ''' % (t['name'], t['condition'], t['error'])
        output.append(tc.strip())
    return output


def generateTests():
    output = []
    test_cases = generateTestCases()
    # LOG.debug(pformat(test_cases, width=260))

    test_statements = []
    for t in test_cases:
        # LOG.debug(pformat(t, width=260))
        # LOG.debug(pformat(t))
        st = makeTestNewAclRuleCondition(t)
        test_statements.extend(st)
    custom_failed_test_statements = makeTestNewAclRuleConditionCustomFailed()
    test_statements.extend(custom_failed_test_statements)

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

    args.code_output.write(code)
    if args.test_output:
        tests = generateTests()
        args.test_output.write(tests)


if __name__ == '__main__':
    main()
