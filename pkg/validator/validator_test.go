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

package validator

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/greenpau/caddy-auth-jwt/internal/tests"
	"github.com/greenpau/caddy-auth-jwt/internal/testutils"
	"github.com/greenpau/caddy-auth-jwt/pkg/acl"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"github.com/greenpau/caddy-auth-jwt/pkg/kms"
	"github.com/greenpau/caddy-auth-jwt/pkg/options"
	"github.com/greenpau/caddy-auth-jwt/pkg/user"
	"github.com/greenpau/caddy-auth-jwt/pkg/utils"

	"github.com/google/go-cmp/cmp"
)

var (

	// Create access list with default deny that allows read:books only
	defaultDenyACL = []*acl.RuleConfiguration{
		{
			Comment: "allow read:books scope",
			Conditions: []string{
				"match scopes read:books",
			},
			Action: `allow log`,
		},
	}

	// Create access list with default allow that denies write:books
	defaultAllowACL = []*acl.RuleConfiguration{
		{
			Comment: "deny write:books scope",
			Conditions: []string{
				"match scopes write:books",
			},
			Action: `deny`,
		},
		{
			Comment: "allow all scopes",
			Conditions: []string{
				"always match scopes any",
			},
			Action: `allow`,
		},
	}

	// Create access list with default deny that allows 127.0.0.1 only
	audienceDefaultDenyACL = []*acl.RuleConfiguration{
		{
			Conditions: []string{
				"match aud https://127.0.0.1:2019/",
			},
			Action: `allow`,
		},
	}

	// Create access list with default allow that denies localhost
	audienceDefaultAllowACL = []*acl.RuleConfiguration{
		{
			Conditions: []string{
				"match aud https://localhost/",
			},
			Action: `deny`,
		},
		{
			Comment: "allow all audiences",
			Conditions: []string{
				"always match audience any",
			},
			Action: `allow`,
		},
	}

	// Create access list with default deny and HTTP Method and Path rules
	customACL = []*acl.RuleConfiguration{
		{
			Conditions: []string{
				"match scope write:books",
				"match method GET",
				"match path /app/page1/blocked",
			},
			Action: `deny`,
		},
		{
			Conditions: []string{
				"match scope write:books",
				"match method GET",
				"match path /app/page2/blocked",
			},
			Action: `deny`,
		},
		{
			Conditions: []string{
				"match scope write:books",
				"match method GET",
				"match path /app/page3/allowed",
			},
			Action: `allow`,
		},
		{
			Conditions: []string{
				"match scope read:books",
			},
			Action: `allow`,
		},
	}

	// Create access list with default deny and mixed claims
	mixedACL = []*acl.RuleConfiguration{
		{
			Conditions: []string{
				"match scope write:books",
			},
			Action: `allow`,
		},
		{
			Conditions: []string{
				"match audience https://127.0.0.1:2019/",
			},
			Action: `allow`,
		},
	}

	// Create viewer persona
	viewer = `{
        "exp": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix()) + `,
        "iat": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute*-1).Unix()) + `,
        "nbf": ` + fmt.Sprintf("%d", time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix()) + `,
        "aud": ["https://127.0.0.1:2019/", "https://google.com/"],
        "sub": "smithj@outlook.com",
        "scope": ["read:books"]
    }`

	editor = `{
        "exp": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix()) + `,
        "iat": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute*-1).Unix()) + `,
        "nbf": ` + fmt.Sprintf("%d", time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix()) + `,
        "aud": "https://localhost/",
        "sub": "jane.smith@outlook.com",
        "scope": ["write:books"]
    }`

	// Create access list with default deny that allows viewer only
	defaultRolesDenyACL = []*acl.RuleConfiguration{
		{
			Conditions: []string{
				"match role viewer",
			},
			Action: `allow`,
		},
	}

	denyViewerAllowOthersACL = []*acl.RuleConfiguration{
		{
			Conditions: []string{
				"match role viewer",
			},
			Action: `deny`,
		},
		{
			Conditions: []string{
				"always match role any",
			},
			Action: `allow`,
		},
	}

	// Create access list with default allow that denies editor
	defaultRolesAllowACL = []*acl.RuleConfiguration{
		{
			Conditions: []string{
				"match role editor",
			},
			Action: `deny`,
		},
		{
			Conditions: []string{
				"always match role any",
			},
			Action: `allow`,
		},
	}

	// Create access list with default deny and HTTP Method and Path rules
	customRolesACL = []*acl.RuleConfiguration{
		{
			Conditions: []string{
				"match role editor",
				"match method GET",
				"match path /app/page1/blocked",
			},
			Action: `deny log`,
		},
		{
			Conditions: []string{
				"match role editor",
				"match method GET",
				"match path /app/page2/blocked",
			},
			Action: `deny log`,
		},
		{
			Conditions: []string{
				"match role editor",
				"match method GET",
				"match path /app/page3/allowed",
			},
			Action: `allow log`,
		},
		{
			Conditions: []string{
				"match role viewer",
			},
			Action: `allow log`,
		},
	}

	// Create viewer persona
	viewer2 = `{
        "exp": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix()) + `,
        "iat": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute*-1).Unix()) + `,
        "nbf": ` + fmt.Sprintf("%d", time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix()) + `,
        "name":   "Smith, John",
        "email":  "smithj@outlook.com",
        "origin": "localhost",
        "sub":    "smithj@outlook.com",
        "roles": ["viewer"],
        "addr": "10.10.10.10"
    }`

	editor2 = `{
        "exp": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix()) + `,
        "iat": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute*-1).Unix()) + `,
        "nbf": ` + fmt.Sprintf("%d", time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix()) + `,
        "name":   "Smith, Jane",
        "email":  "jane.smith@outlook.com",
        "origin": "localhost",
        "sub":    "jane.smith@outlook.com",
        "roles": ["editor"]
    }`

	viewer3 = `{
        "exp": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix()) + `,
        "iat": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute*-1).Unix()) + `,
        "nbf": ` + fmt.Sprintf("%d", time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix()) + `,
        "name":   "Smith, John",
        "email":  "smithj@outlook.com",
        "origin": "localhost",
        "sub":    "smithj@outlook.com",
        "roles": ["viewer"],
		"acl":{
			"paths": {
				"/**/allowed": {}
			}
		}
    }`

	viewer4 = `{
        "exp": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix()) + `,
        "iat": ` + fmt.Sprintf("%d", time.Now().Add(10*time.Minute*-1).Unix()) + `,
        "nbf": ` + fmt.Sprintf("%d", time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix()) + `,
        "name":   "Smith, John",
        "email":  "smithj@outlook.com",
        "origin": "localhost",
        "sub":    "smithj@outlook.com",
        "roles": ["viewer"],
        "addr": "10.10.10.10",
        "acl":{
            "paths": {
                "/**/allowed": {}
            }
        }
    }`
)

func TestAuthorize(t *testing.T) {
	testcases := []struct {
		name string
		// disabled                    bool
		claims                      string
		config                      []*acl.RuleConfiguration
		method                      string
		path                        string
		sourceAddress               string
		enableBearer                bool
		cacheUser                   bool
		validateAccessListPathClaim bool
		validateSourceAddress       bool
		validateMethodPath          bool
		optionsDisabled             bool
		want                        map[string]interface{}
		shouldErr                   bool
		err                         error
	}{
		// Access list with default deny that allows viewer only
		{
			name:   "user with viewer scope claim and default deny acl",
			claims: viewer, config: defaultDenyACL, method: "GET", path: "/app/viewer", shouldErr: false,
			validateMethodPath: true,
		},
		{
			name:   "user with editor scope claim and default deny acl",
			claims: editor, config: defaultDenyACL, method: "GET", path: "/app/viewer", shouldErr: true, err: errors.ErrAccessNotAllowed,
			validateMethodPath: true,
		},
		// Access list with default allow that denies editor
		{
			name:   "user with viewer scope claim and default allow acl",
			claims: viewer, config: defaultAllowACL, method: "GET", path: "/app/viewer", shouldErr: false,
			validateMethodPath: true,
		},
		{
			name:   "user with editor scope claim and default allow acl",
			claims: editor, config: defaultAllowACL, method: "GET", path: "/app/viewer", shouldErr: true, err: errors.ErrAccessNotAllowed,
			validateMethodPath: true,
		},
		// Access list with default deny that allows 127.0.0.1 only
		{
			name:   "user with viewer scope claim and audience deny acl",
			claims: viewer, config: audienceDefaultDenyACL, method: "GET", path: "/app/viewer", shouldErr: false,
			validateMethodPath: true,
		},
		{
			name:   "user with editor scope claim and audience deny acl",
			claims: editor, config: audienceDefaultDenyACL, method: "GET", path: "/app/viewer", shouldErr: true, err: errors.ErrAccessNotAllowed,
			validateMethodPath: true,
		},
		// Access list with default allow that denies localhost
		{
			name:   "user with viewer scope claim and audience allow acl",
			claims: viewer, config: audienceDefaultAllowACL, method: "GET", path: "/app/viewer", shouldErr: false,
			validateMethodPath: true,
		},
		{
			name:   "user with editor scope claim and audience allow acl",
			claims: editor, config: audienceDefaultAllowACL, method: "GET", path: "/app/viewer", shouldErr: true, err: errors.ErrAccessNotAllowed,
			validateMethodPath: true,
		},
		// Custom ACL
		{
			name:   "user with viewer scope claim and custom acl going to /app/page1/blocked via get",
			claims: viewer, config: customACL, method: "GET", path: "/app/page1/blocked", shouldErr: false,
			validateMethodPath: true,
		},
		{
			name:   "user with viewer scope claim and custom acl going to /app/page2/blocked via get",
			claims: viewer, config: customACL, method: "GET", path: "/app/page2/blocked", shouldErr: false,
			validateMethodPath: true,
		},
		{
			name:   "user with viewer scope claim and custom acl going to /app/page3/allowed via get",
			claims: viewer, config: customACL, method: "GET", path: "/app/page3/allowed", shouldErr: false,
			validateMethodPath: true,
		},
		{
			name:   "user with editor scope claim and custom acl going to /app/page1/blocked via get",
			claims: editor, config: customACL, method: "GET", path: "/app/page1/blocked", shouldErr: true, err: errors.ErrAccessNotAllowed,
			validateMethodPath: true,
		},
		{
			name:   "user with editor scope claim and custom acl going to /app/page2/blocked via get",
			claims: editor, config: customACL, method: "GET", path: "/app/page2/blocked", shouldErr: true, err: errors.ErrAccessNotAllowed,
			validateMethodPath: true,
		},
		{
			name:   "user with editor scope claim and custom acl going to /app/page3/allowed via get",
			claims: editor, config: customACL, method: "GET", path: "/app/page3/allowed", shouldErr: false,
			validateMethodPath: true,
		},
		// Mixed ACL
		{
			name:   "user with viewer scope and audience claims and custom acl",
			claims: viewer, config: mixedACL, method: "GET", path: "/app/page1/blocked", shouldErr: false,
			validateMethodPath: true,
		},
		{
			name:   "user with editor scope and localhost audience claims and mixed acl",
			claims: editor, config: mixedACL, method: "GET", path: "/app/editor", shouldErr: false,
			validateMethodPath: true,
		},
		// Role-based ACLs.
		{
			name:   "user with viewer role claim and default deny acl going to app/viewer via get",
			claims: viewer2, config: defaultRolesDenyACL, method: "GET", path: "/app/viewer", shouldErr: false,
			enableBearer:       true,
			validateMethodPath: true,
		},
		{
			name:   "user with viewer role claim and default deny acl going to app/editor via get",
			claims: viewer2, config: defaultRolesDenyACL, method: "GET", path: "/app/editor", shouldErr: false,
			enableBearer:       true,
			validateMethodPath: true,
		},
		{
			name:   "user with viewer role claim and default deny acl going to app/admin via get",
			claims: viewer2, config: defaultRolesDenyACL, method: "GET", path: "/app/admin", shouldErr: false,
			enableBearer:       true,
			validateMethodPath: true,
		},
		{
			name:   "user with editor role claim and default deny acl going to app/viewer via get",
			claims: editor2, config: defaultRolesDenyACL, method: "GET", path: "/app/viewer", shouldErr: true, err: errors.ErrAccessNotAllowed,
			enableBearer:       true,
			validateMethodPath: true,
		},
		{
			name:   "user with editor role claim and default deny acl going to app/editor via get",
			claims: editor2, config: defaultRolesDenyACL, method: "GET", path: "/app/editor", shouldErr: true, err: errors.ErrAccessNotAllowed,
			enableBearer:       true,
			validateMethodPath: true,
		},
		{
			name:   "user with editor role claim and default deny acl going to app/admin via get",
			claims: editor2, config: defaultRolesDenyACL, method: "GET", path: "/app/admin", shouldErr: true, err: errors.ErrAccessNotAllowed,
			enableBearer:       true,
			validateMethodPath: true,
		},
		// Access list with default allow that denies editor
		{
			name:   "user with viewer role claim and default allow acl going to app/viewer via get",
			claims: viewer2, config: defaultRolesAllowACL, method: "GET", path: "/app/viewer", shouldErr: false,
			enableBearer:       true,
			validateMethodPath: true,
		},
		{
			name:   "user with viewer role claim and default allow acl going to app/editor via get",
			claims: viewer2, config: defaultRolesAllowACL, method: "GET", path: "/app/editor", shouldErr: false,
			enableBearer:       true,
			validateMethodPath: true,
		},
		{
			name:   "user with viewer role claim and default allow acl going to app/admin via get",
			claims: viewer2, config: defaultRolesAllowACL, method: "GET", path: "/app/admin", shouldErr: false,
			enableBearer:       true,
			validateMethodPath: true,
		},
		{
			name:   "user with editor role claim and default allow acl going to app/viewer via get",
			claims: editor2, config: defaultRolesAllowACL, method: "GET", path: "/app/viewer", shouldErr: true, err: errors.ErrAccessNotAllowed,
			enableBearer:       true,
			validateMethodPath: true,
		},
		{
			name:   "user with editor role claim and default allow acl going to app/editor via get",
			claims: editor2, config: defaultRolesAllowACL, method: "GET", path: "/app/editor", shouldErr: true, err: errors.ErrAccessNotAllowed,
			enableBearer:       true,
			validateMethodPath: true,
		},
		{
			name:   "user with editor role claim and default allow acl going to app/admin via get",
			claims: editor2, config: defaultRolesAllowACL, method: "GET", path: "/app/admin", shouldErr: true, err: errors.ErrAccessNotAllowed,
			enableBearer:       true,
			validateMethodPath: true,
		},
		// Custom ACL
		{
			name:   "user with editor role claim and custom acl going to /app/page1/blocked via get",
			claims: editor2, config: customRolesACL, method: "GET", path: "/app/page1/blocked", shouldErr: true, err: errors.ErrAccessNotAllowed,
			enableBearer:       true,
			validateMethodPath: true,
		},
		{
			name:   "user with editor role claim and custom acl going to /app/page2/blocked via get",
			claims: editor2, config: customRolesACL, method: "GET", path: "/app/page2/blocked", shouldErr: true, err: errors.ErrAccessNotAllowed,
			enableBearer:       true,
			validateMethodPath: true,
		},
		{
			name:   "user with editor role claim and custom acl going to /app/page3/allowed via get",
			claims: editor2, config: customRolesACL, method: "GET", path: "/app/page3/allowed", shouldErr: false,
			enableBearer:       true,
			validateMethodPath: true,
		},
		{
			name:   "user with viewer role claim and custom acl going to /app/page1/blocked via get",
			claims: viewer2, config: customRolesACL, method: "GET", path: "/app/page1/blocked", shouldErr: false,
			enableBearer:       true,
			validateMethodPath: true,
		},
		{
			name:   "user with viewer role claim and custom acl going to /app/page2/blocked via get",
			claims: viewer2, config: customRolesACL, method: "GET", path: "/app/page2/blocked", shouldErr: false,
			enableBearer:       true,
			validateMethodPath: true,
		},
		{
			name:   "user with viewer role claim and custom acl going to /app/page3/allowed via get",
			claims: viewer2, config: customRolesACL, method: "GET", path: "/app/page3/allowed", shouldErr: false,
			enableBearer:       true,
			validateMethodPath: true,
		},
		// Token based ACL
		{
			name:                        "user with viewer role claim and token-based acl going to /app/page3/allowed via get with src addr",
			claims:                      viewer4,
			config:                      defaultRolesDenyACL,
			method:                      "GET",
			path:                        "/app/page3/allowed",
			shouldErr:                   false,
			validateAccessListPathClaim: true,
			validateMethodPath:          true,
			validateSourceAddress:       true,
			sourceAddress:               "10.10.10.10",
		},
		{
			name:                        "user with viewer role claim and token-based acl going to /app/page3/allowed via get with src addr and block path acl",
			claims:                      viewer4,
			config:                      defaultRolesDenyACL,
			method:                      "GET",
			path:                        "/app/page3/blocked",
			validateAccessListPathClaim: true,
			validateMethodPath:          true,
			validateSourceAddress:       true,
			sourceAddress:               "10.10.10.10",
			shouldErr:                   true,
			err:                         errors.ErrAccessNotAllowedByPathACL,
		},
		{
			name:                        "user with viewer role claim and token-based acl going to /app/page3/allowed via get with acl block with src addr",
			claims:                      viewer3,
			config:                      denyViewerAllowOthersACL,
			method:                      "GET",
			path:                        "/app/page3/denied",
			validateAccessListPathClaim: true,
			validateMethodPath:          true,
			validateSourceAddress:       true,
			sourceAddress:               "10.10.10.10",
			shouldErr:                   true,
			err:                         errors.ErrAccessNotAllowed,
		},
		{
			name:                        "user with viewer role claim and token-based acl going to /app/page3/allowed via get with acl block with src addr",
			claims:                      viewer2,
			config:                      defaultRolesAllowACL,
			method:                      "GET",
			path:                        "/app/page3/denied",
			validateAccessListPathClaim: true,
			validateMethodPath:          true,
			validateSourceAddress:       true,
			sourceAddress:               "10.10.10.10",
			shouldErr:                   true,
			err:                         errors.ErrAccessNotAllowedByPathACL,
		},
		{
			name:                        "user with viewer role claim and token-based acl going to /app/page3/allowed via get with acl block with src addr mismatch",
			claims:                      viewer2,
			config:                      defaultRolesAllowACL,
			method:                      "GET",
			path:                        "/app/page3/denied",
			validateAccessListPathClaim: true,
			validateMethodPath:          true,
			validateSourceAddress:       true,
			sourceAddress:               "20.20.20.20",
			shouldErr:                   true,
			err:                         errors.ErrSourceAddressMismatch.WithArgs("10.10.10.10", "20.20.20.20"),
		},
		{
			name:                        "user with viewer role claim and token-based acl going to /app/page3/allowed via get",
			claims:                      viewer3,
			config:                      defaultRolesDenyACL,
			method:                      "GET",
			path:                        "/app/page3/allowed",
			shouldErr:                   false,
			validateAccessListPathClaim: true,
			validateMethodPath:          true,
		},
		{
			name:                        "user with viewer role claim and token-based acl going to /app/page3/allowed via get with acl block",
			claims:                      viewer3,
			config:                      denyViewerAllowOthersACL,
			method:                      "GET",
			path:                        "/app/page3/denied",
			validateAccessListPathClaim: true,
			validateMethodPath:          true,
			shouldErr:                   true,
			err:                         errors.ErrAccessNotAllowed,
		},
		{
			name:                        "user with viewer role claim and token-based acl going to /app/page3/allowed via get with acl block",
			claims:                      viewer2,
			config:                      defaultRolesAllowACL,
			method:                      "GET",
			path:                        "/app/page3/denied",
			validateAccessListPathClaim: true,
			validateMethodPath:          true,
			shouldErr:                   true,
			err:                         errors.ErrAccessNotAllowedByPathACL,
		},
		{
			name:                        "user with viewer role claim and token-based acl going to /app/page3/allowed via get with deny acl",
			claims:                      viewer3,
			config:                      defaultRolesDenyACL,
			method:                      "GET",
			path:                        "/app/page3/denied",
			validateAccessListPathClaim: true,
			shouldErr:                   true,
			err:                         errors.ErrAccessNotAllowedByPathACL,
		},
		{
			name:                        "user with viewer role claim and token-based acl going to /app/page3/allowed via get without method and path",
			claims:                      viewer3,
			config:                      denyViewerAllowOthersACL,
			validateAccessListPathClaim: true,
			method:                      "GET",
			path:                        "/app/page3/allowed",
			shouldErr:                   true,
			err:                         errors.ErrAccessNotAllowed,
		},
		{
			name:                        "user with viewer role claim and token-based acl going to /app/page3/allowed via get with src addr",
			claims:                      viewer3,
			config:                      defaultRolesDenyACL,
			method:                      "GET",
			path:                        "/app/page3/allowed",
			validateAccessListPathClaim: true,
			validateSourceAddress:       true,
			shouldErr:                   true,
			err:                         errors.ErrSourceAddressNotFound,
		},
		{
			name:                        "user with viewer role claim and token-based acl going to /app/page3/allowed via get with deny acl and with src addr and no ip match",
			claims:                      viewer4,
			config:                      defaultRolesDenyACL,
			method:                      "GET",
			path:                        "/app/page3/denied",
			validateAccessListPathClaim: true,
			validateSourceAddress:       true,
			sourceAddress:               "20.20.20.20",
			shouldErr:                   true,
			err:                         errors.ErrSourceAddressMismatch.WithArgs("10.10.10.10", "20.20.20.20"),
		},
		{
			name:                        "user with viewer role claim and token-based acl going to /app/page3/allowed via get with deny acl and with src addr and ip match",
			claims:                      viewer4,
			config:                      defaultRolesDenyACL,
			method:                      "GET",
			path:                        "/app/page3/allowed",
			validateAccessListPathClaim: true,
			validateSourceAddress:       true,
			sourceAddress:               "10.10.10.10",
		},
		{
			name:                        "user with viewer role claim and token-based acl going to /app/page3/allowed via get with deny acl and with src addr and no ip block",
			claims:                      viewer4,
			config:                      defaultRolesDenyACL,
			method:                      "GET",
			path:                        "/app/page3/denied",
			validateAccessListPathClaim: true,
			validateSourceAddress:       true,
			sourceAddress:               "10.10.10.10",
			shouldErr:                   true,
			err:                         errors.ErrAccessNotAllowedByPathACL,
		},
		{
			name:                        "user with viewer role claim and token-based acl going to /app/page3/allowed via get with deny acl and with src addr and no acl",
			claims:                      viewer2,
			config:                      defaultRolesDenyACL,
			method:                      "GET",
			path:                        "/app/page3/denied",
			validateAccessListPathClaim: true,
			validateSourceAddress:       true,
			sourceAddress:               "10.10.10.10",
			shouldErr:                   true,
			err:                         errors.ErrAccessNotAllowedByPathACL,
		},
		{
			name:                        "user with viewer role claim and token-based acl going to /app/page3/allowed via get without method and path and with src addr",
			claims:                      viewer3,
			config:                      denyViewerAllowOthersACL,
			validateAccessListPathClaim: true,
			validateSourceAddress:       true,
			method:                      "GET",
			path:                        "/app/page3/allowed",
			shouldErr:                   true,
			err:                         errors.ErrAccessNotAllowed,
		},

		{
			name:                        "user with viewer role claim and token-based acl going to /app/page3/allowed via get without acl",
			claims:                      viewer,
			config:                      defaultRolesAllowACL,
			validateAccessListPathClaim: true,
			method:                      "GET",
			path:                        "/app/page3/allowed",
			shouldErr:                   true,
			err:                         errors.ErrAccessNotAllowedByPathACL,
		},
		{
			name:                        "user with viewer role claim and token-based acl going to /app/page3/allowed via get without method and path",
			claims:                      viewer3,
			config:                      defaultRolesDenyACL,
			method:                      "GET",
			path:                        "/app/page3/allowed",
			shouldErr:                   false,
			validateAccessListPathClaim: true,
		},
		{
			name:                        "user with viewer role claim and token-based acl going to /app/page3/allowed via get with source address",
			claims:                      viewer3,
			config:                      defaultRolesDenyACL,
			method:                      "GET",
			path:                        "/app/page3/allowed",
			shouldErr:                   true,
			err:                         errors.ErrSourceAddressNotFound,
			validateAccessListPathClaim: true,
			validateSourceAddress:       true,
			validateMethodPath:          true,
		},
		{
			name:                        "user with viewer role claim and token-based acl going to /app/page3/allowed via get with source address and without method and path",
			claims:                      viewer3,
			config:                      defaultRolesDenyACL,
			method:                      "GET",
			path:                        "/app/page3/allowed",
			shouldErr:                   true,
			err:                         errors.ErrSourceAddressNotFound,
			validateAccessListPathClaim: true,
			validateSourceAddress:       true,
		},
		{
			name:                        "user with viewer role claim and token-based acl going to /app/page2/blocked via get",
			claims:                      viewer3,
			config:                      defaultRolesDenyACL,
			method:                      "GET",
			path:                        "/app/page2/blocked",
			validateAccessListPathClaim: true,
			validateMethodPath:          true,
			shouldErr:                   true,
			err:                         errors.ErrAccessNotAllowedByPathACL,
		},
		{
			name:      "user with viewer role claim going to /app/page2/blocked via get",
			claims:    viewer3,
			config:    denyViewerAllowOthersACL,
			method:    "GET",
			path:      "/app/page2/blocked",
			shouldErr: true,
			err:       errors.ErrAccessNotAllowed,
		},
		{
			name:               "access list not set",
			claims:             viewer,
			method:             "GET",
			path:               "/app/page3/allowed",
			validateMethodPath: true,
			shouldErr:          true,
			err:                errors.ErrNoAccessList,
		},
		{
			name:               "empty token",
			config:             defaultAllowACL,
			method:             "GET",
			path:               "/app/page3/allowed",
			validateMethodPath: true,
			shouldErr:          true,
			err:                errors.ErrNoTokenFound,
			// ErrValidatorInvalidToken.WithArgs(errors.ErrCryptoKeyStoreParseTokenFailed),
		},
		{
			name:               "bad token",
			config:             defaultAllowACL,
			method:             "GET",
			path:               "/app/page3/allowed",
			validateMethodPath: true,
			shouldErr:          true,
			// err:       errors.ErrNoTokenFound,
			err: errors.ErrValidatorInvalidToken.WithArgs(errors.ErrCryptoKeyStoreParseTokenFailed),
		},
		{
			name:               "no acl rules",
			claims:             viewer,
			config:             defaultAllowACL,
			method:             "GET",
			path:               "/app/page3/allowed",
			validateMethodPath: true,
			shouldErr:          true,
			err:                errors.ErrAccessListNoRules,
		},
		{
			name:               "no verify keys",
			claims:             viewer,
			config:             defaultAllowACL,
			method:             "GET",
			path:               "/app/page3/allowed",
			validateMethodPath: true,
			shouldErr:          true,
			err:                errors.ErrValidatorCryptoKeyStoreNoKeys,
		},
		{
			name:                  "token without ip address",
			claims:                viewer,
			config:                defaultAllowACL,
			method:                "GET",
			path:                  "/app/page3/allowed",
			validateSourceAddress: true,
			shouldErr:             true,
			err:                   errors.ErrSourceAddressNotFound,
		},
		{
			name:                  "token ip address and client ip address not match",
			claims:                viewer2,
			config:                defaultRolesAllowACL,
			method:                "GET",
			path:                  "/app/page3/allowed",
			validateSourceAddress: true,
			sourceAddress:         "20.20.20.20",
			shouldErr:             true,
			err:                   errors.ErrSourceAddressMismatch.WithArgs("10.10.10.10", "20.20.20.20"),
		},
		{
			name:                  "token ip address and client ip address match",
			claims:                viewer2,
			config:                defaultRolesAllowACL,
			method:                "GET",
			path:                  "/app/page3/allowed",
			validateSourceAddress: true,
			sourceAddress:         "10.10.10.10",
		},
		{
			name:      "cached user",
			claims:    viewer2,
			config:    defaultRolesAllowACL,
			method:    "GET",
			path:      "/app/page3/allowed",
			cacheUser: true,
		},
		{
			name:                  "token ip address and client ip address match but not roles",
			claims:                viewer2,
			config:                denyViewerAllowOthersACL,
			method:                "GET",
			path:                  "/app/page3/allowed",
			validateSourceAddress: true,
			sourceAddress:         "10.10.10.10",
			shouldErr:             true,
			err:                   errors.ErrAccessNotAllowed,
		},
		{
			name:                  "token without ip address with method and path",
			claims:                viewer,
			config:                defaultAllowACL,
			method:                "GET",
			path:                  "/app/page3/allowed",
			validateSourceAddress: true,
			validateMethodPath:    true,
			shouldErr:             true,
			err:                   errors.ErrSourceAddressNotFound,
		},
		{
			name:                  "token without ip address with method and path and with acl block",
			claims:                viewer,
			config:                defaultRolesDenyACL,
			method:                "GET",
			path:                  "/app/page3/allowed",
			validateSourceAddress: true,
			validateMethodPath:    true,
			shouldErr:             true,
			err:                   errors.ErrAccessNotAllowed,
		},
		{
			name:                  "token without ip address with method and path and without acl block",
			claims:                viewer2,
			config:                defaultRolesAllowACL,
			method:                "GET",
			path:                  "/app/page3/allowed",
			validateSourceAddress: true,
			validateMethodPath:    true,
			sourceAddress:         "10.10.10.10",
		},
		{
			name:                  "token ip address and client ip address not match with method and path",
			claims:                viewer2,
			config:                defaultRolesAllowACL,
			method:                "GET",
			path:                  "/app/page3/allowed",
			validateSourceAddress: true,
			validateMethodPath:    true,
			sourceAddress:         "20.20.20.20",
			shouldErr:             true,
			err:                   errors.ErrSourceAddressMismatch.WithArgs("10.10.10.10", "20.20.20.20"),
		},
		{
			name:            "validator options disabled",
			claims:          viewer,
			config:          defaultAllowACL,
			method:          "GET",
			path:            "/app/page3/allowed",
			optionsDisabled: true,
			shouldErr:       true,
			err:             errors.ErrTokenValidatorOptionsNotFound,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			//if tc.disabled {
			//	return
			// }
			var accessList *acl.AccessList
			var opts *options.TokenValidatorOptions
			var token string
			ctx := context.Background()
			logger := utils.NewLogger()

			ks := testutils.NewTestCryptoKeyStore()
			keys := ks.GetKeys()
			signingKey := keys[0]

			validator := NewTokenValidator()

			if !tc.optionsDisabled {
				opts = options.NewTokenValidatorOptions()
				if tc.enableBearer {
					opts.ValidateBearerHeader = true
				}
				if tc.validateAccessListPathClaim {
					opts.ValidateAccessListPathClaim = true
				}
				if tc.validateSourceAddress {
					opts.ValidateSourceAddress = true
				}
				if tc.validateMethodPath {
					opts.ValidateMethodPath = true
				}
			}

			if len(tc.config) > 0 {
				accessList = acl.NewAccessList()
				accessList.SetLogger(logger)
				if tc.name != "no acl rules" {
					if err := accessList.AddRules(ctx, tc.config); err != nil {
						t.Fatal(err)
					}
				}
			}

			if tc.name == "no verify keys" {
				keys = []*kms.CryptoKey{}
			}

			if err := validator.Configure(ctx, keys, accessList, opts); err != nil {
				if tests.EvalErr(t, err, tc.config, tc.shouldErr, tc.err) {
					return
				}
			}

			if tc.want == nil {
				tc.want = make(map[string]interface{})
			}

			if tc.claims != "" {
				usr, err := user.NewUser(tc.claims)
				if err != nil {
					t.Fatal(err)
				}
				tc.want["claims"] = usr.Claims
				if err := signingKey.SignToken("HS512", usr); err != nil {
					t.Fatal(err)
				}
				token = usr.Token
			}

			if tc.name == "bad token" {
				token = `{"foobar", "barfoo"}`
			}

			if tc.enableBearer {
				tc.want["token_name"] = "bearer"
			} else {
				tc.want["token_name"] = "access_token"
			}

			handler := func(w http.ResponseWriter, r *http.Request) {
				ctx := context.Background()
				var msgs []string
				msgs = append(msgs, fmt.Sprintf("test name: %s", tc.name))
				for _, entry := range tc.config {
					msgs = append(msgs, fmt.Sprintf("ACL: %+v", entry))
				}
				msgs = append(msgs, fmt.Sprintf("claims: %+v", tc.claims))
				msgs = append(msgs, fmt.Sprintf("path: %s", r.URL.Path))
				msgs = append(msgs, fmt.Sprintf("method: %s", r.Method))
				msgs = append(msgs, fmt.Sprintf("key\n%s", cmp.Diff(nil, keys[0])))
				usr, err := validator.Authorize(ctx, r)
				if tests.EvalErrWithLog(t, err, tc.config, tc.shouldErr, tc.err, msgs) {
					return
				}
				got := make(map[string]interface{})
				got["token_name"] = usr.TokenName
				got["claims"] = usr.Claims
				tests.EvalObjectsWithLog(t, "eval", tc.want, got, msgs)

				if tc.shouldErr {
					return
				}

				if tc.cacheUser {
					if err := validator.CacheUser(usr); err != nil {
						if tests.EvalErrWithLog(t, err, "cache user", tc.shouldErr, tc.err, msgs) {
							return
						}
					}
					usr, err = validator.Authorize(ctx, r)
					if tests.EvalErrWithLog(t, err, "cached auth", tc.shouldErr, tc.err, msgs) {
						return
					}
				}
			}

			req, err := http.NewRequest(tc.method, tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}

			if tc.enableBearer {
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
			} else {
				req.Header.Set("Authorization", fmt.Sprintf("access_token=%s", token))
			}

			if tc.sourceAddress != "" {
				req.Header.Set("X-Real-Ip", tc.sourceAddress)
			}

			w := httptest.NewRecorder()
			handler(w, req)
			w.Result()
		})
	}
}

func TestAddKeys(t *testing.T) {
	testcases := []struct {
		name                 string
		keys                 []*kms.CryptoKey
		verifyFound          bool
		verifyNotCapable     bool
		verifyNoTokenName    bool
		verifyNoMaxLifetime  bool
		verifyEmptyTokenName bool
		shouldErr            bool
		err                  error
	}{
		{
			name:      "no keys",
			shouldErr: true,
			err:       errors.ErrValidatorCryptoKeyStoreNoKeys,
		},
		{
			name: "add keys",
			keys: []*kms.CryptoKey{
				&kms.CryptoKey{},
			},
			verifyFound: true,
		},
		{
			name: "add non verify key",
			keys: []*kms.CryptoKey{
				&kms.CryptoKey{},
			},
			verifyFound:      true,
			verifyNotCapable: true,
			shouldErr:        true,
			err:              errors.ErrValidatorCryptoKeyStoreNoVerifyKeys,
		},
		{
			name: "add key without token name",
			keys: []*kms.CryptoKey{
				&kms.CryptoKey{},
			},
			verifyFound:       true,
			verifyNoTokenName: true,
			shouldErr:         true,
			err:               errors.ErrValidatorCryptoKeyStoreNoVerifyKeys,
		},
		{
			name: "add key without token lifetime",
			keys: []*kms.CryptoKey{
				&kms.CryptoKey{},
			},
			verifyFound:         true,
			verifyNoMaxLifetime: true,
			shouldErr:           true,
			err:                 errors.ErrValidatorCryptoKeyStoreNoVerifyKeys,
		},
		{
			name: "add key with empty token name with spaces",
			keys: []*kms.CryptoKey{
				&kms.CryptoKey{},
			},
			verifyFound:          true,
			verifyEmptyTokenName: true,
			shouldErr:            true,
			err:                  errors.ErrEmptyTokenName,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			ctx := context.Background()
			validator := NewTokenValidator()
			for _, k := range tc.keys {
				if tc.verifyFound {
					k.Verify = kms.NewCryptoKeyOperator()
					k.Verify.Token.Capable = true
					k.Verify.Token.Name = "access_token"
					k.Verify.Token.MaxLifetime = 900
				}
				if tc.verifyNotCapable {
					k.Verify.Token.Capable = false
				}
				if tc.verifyNoTokenName {
					k.Verify.Token.Name = ""
				}
				if tc.verifyNoMaxLifetime {
					k.Verify.Token.MaxLifetime = 0
				}
				if tc.verifyEmptyTokenName {
					k.Verify.Token.Name = "    "
				}
			}
			err = validator.addKeys(ctx, tc.keys)
			if tests.EvalErr(t, err, "keys", tc.shouldErr, tc.err) {
				return
			}
		})
	}
}

func TestSetAllowedTokenNames(t *testing.T) {
	testcases := []struct {
		name       string
		tokenNames []string
		want       map[string]interface{}
		shouldErr  bool
		err        error
	}{
		{
			name:       "token names slice with duplicate values",
			tokenNames: []string{"foo", "foo"},
			shouldErr:  true,
			err:        errors.ErrDuplicateTokenName.WithArgs("foo"),
		},
		{
			name:       "token names slice with empty values",
			tokenNames: []string{"foo", ""},
			shouldErr:  true,
			err:        errors.ErrEmptyTokenName,
		},
		{
			name:       "valid token names",
			tokenNames: []string{"foo", "bar"},
			want: map[string]interface{}{
				"header": map[string]interface{}{
					"foo": true,
					"bar": true,
				},
				"cookie": map[string]interface{}{
					"foo": true,
					"bar": true,
				},
				"query": map[string]interface{}{
					"foo": true,
					"bar": true,
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			validator := NewTokenValidator()
			err := validator.setAllowedTokenNames(tc.tokenNames)
			if tests.EvalErr(t, err, "token names", tc.shouldErr, tc.err) {
				return
			}
			got := make(map[string]interface{})
			got["header"] = validator.authHeaders
			got["cookie"] = validator.GetAuthCookies()
			got["query"] = validator.authHeaders
			tests.EvalObjects(t, "token names", tc.want, got)
		})
	}
}

func TestSetSourcePriority(t *testing.T) {
	testcases := []struct {
		name      string
		sources   []string
		want      map[string]interface{}
		shouldErr bool
		err       error
	}{
		{
			name:      "empty allowed token sources slice",
			shouldErr: true,
			err:       errors.ErrInvalidSourcePriority,
		},
		{
			name:      "allowed token sources slice exceeds three values",
			shouldErr: true,
			sources:   []string{"foo", "foo", "foo", "foo"},
			err:       errors.ErrInvalidSourcePriority,
		},
		{
			name:      "allowed token sources slice has invalid source",
			sources:   []string{"header", "cookie", "foo"},
			shouldErr: true,
			err:       errors.ErrInvalidSourceName.WithArgs("foo"),
		},
		{
			name:      "allowed token sources slice has duplicate source",
			sources:   []string{"header", "query", "query"},
			shouldErr: true,
			err:       errors.ErrDuplicateSourceName.WithArgs("query"),
		},
		{
			name:    "reorder token source priority",
			sources: []string{"header", "cookie", "query"},
			want: map[string]interface{}{
				"sources": []string{"header", "cookie", "query"},
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			validator := NewTokenValidator()
			err := validator.SetSourcePriority(tc.sources)
			if tests.EvalErr(t, err, "token sources", tc.shouldErr, tc.err) {
				return
			}
			got := make(map[string]interface{})
			got["sources"] = validator.GetSourcePriority()
			tests.EvalObjects(t, "token sources", tc.want, got)
		})
	}
}
