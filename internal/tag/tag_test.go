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

package tag

import (
	"bufio"
	"fmt"
	"github.com/greenpau/caddy-auth-jwt"
	"github.com/greenpau/caddy-auth-jwt/internal/tests"
	"github.com/greenpau/caddy-auth-jwt/internal/testutils"
	"github.com/greenpau/caddy-auth-jwt/pkg/acl"
	"github.com/greenpau/caddy-auth-jwt/pkg/authz"
	"github.com/greenpau/caddy-auth-jwt/pkg/cache"
	"github.com/greenpau/caddy-auth-jwt/pkg/kms"
	"github.com/greenpau/caddy-auth-jwt/pkg/options"
	"github.com/greenpau/caddy-auth-jwt/pkg/user"
	"github.com/greenpau/caddy-auth-jwt/pkg/validator"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestTagCompliance(t *testing.T) {
	testcases := []struct {
		name      string
		entry     interface{}
		opts      *Options
		shouldErr bool
		err       error
	}{
		{
			name:  "test user.Checkpoint struct",
			entry: &user.Checkpoint{},
			opts:  &Options{},
		},
		{
			name:  "test cache.TokenCache struct",
			entry: &cache.TokenCache{},
			opts:  &Options{},
		},
		{
			name:  "test user.User struct",
			entry: &user.User{},
			opts:  &Options{},
		},
		{
			name:  "test user.Authenticator struct",
			entry: &user.Authenticator{},
			opts:  &Options{},
		},
		{
			name:  "test testutils.InjectedTestToken struct",
			entry: &testutils.InjectedTestToken{},
			opts:  &Options{},
		},
		{
			name:  "test acl.AccessList struct",
			entry: &acl.AccessList{},
			opts:  &Options{},
		},
		{
			name:  "test acl.RuleConfiguration struct",
			entry: &acl.RuleConfiguration{},
			opts:  &Options{},
		},
		{
			name:  "test authz.InstanceManager struct",
			entry: &authz.InstanceManager{},
			opts:  &Options{},
		},
		{
			name:  "test kms.CryptoKey struct",
			entry: &kms.CryptoKey{},
			opts:  &Options{},
		},
		{
			name:  "test kms.CryptoKeyOperator struct",
			entry: &kms.CryptoKeyOperator{},
			opts:  &Options{},
		},
		{
			name:  "test options.TokenGrantorOptions struct",
			entry: &options.TokenGrantorOptions{},
			opts:  &Options{},
		},
		{
			name:  "test user.Claims struct",
			entry: &user.Claims{},
			opts: &Options{
				DisableTagMismatch: true,
			},
		},
		{
			name:  "test jwt.AuthMiddleware struct",
			entry: &jwt.AuthMiddleware{},
			opts:  &Options{},
		},
		{
			name:  "test user.AccessListClaim struct",
			entry: &user.AccessListClaim{},
			opts:  &Options{},
		},
		{
			name:  "test validator.TokenValidator struct",
			entry: &validator.TokenValidator{},
			opts:  &Options{},
		},
		{
			name:  "test authz.Authorizer struct",
			entry: &authz.Authorizer{},
			opts: &Options{
				DisableTagMismatch: true,
			},
		},
		{
			name:  "test kms.CryptoKeyConfig struct",
			entry: &kms.CryptoKeyConfig{},
			opts: &Options{
				DisableTagMismatch: true,
			},
		},
		{
			name:  "test kms.CryptoKeyTokenOperator struct",
			entry: &kms.CryptoKeyTokenOperator{},
			opts:  &Options{},
		},
		{
			name:  "test kms.CryptoKeyStore struct",
			entry: &kms.CryptoKeyStore{},
			opts:  &Options{},
		},
		{
			name:  "test options.TokenValidatorOptions struct",
			entry: &options.TokenValidatorOptions{},
			opts:  &Options{},
		},
		{
			name:  "test authz.BypassConfig struct",
			entry: &authz.BypassConfig{},
			opts:  &Options{},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs, err := GetTagCompliance(tc.entry, tc.opts)
			if tests.EvalErrWithLog(t, err, nil, tc.shouldErr, tc.err, msgs) {
				return
			}
		})
	}
}

func TestStructTagCompliance(t *testing.T) {
	var files []string
	structMap := make(map[string]bool)
	walkFn := func(path string, fileInfo os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fileInfo.IsDir() {
			return nil
		}
		fileName := filepath.Base(path)
		fileExt := filepath.Ext(fileName)
		if fileExt != ".go" {
			return nil
		}
		if strings.Contains(fileName, "_test.go") {
			return nil
		}
		if strings.Contains(path, "/tag/") || strings.Contains(path, "/errors/") {
			return nil
		}
		// t.Logf("%s %d", path, fileInfo.Size())
		files = append(files, path)
		return nil
	}
	if err := filepath.Walk("../../", walkFn); err != nil {
		t.Error(err)
	}

	for _, fp := range files {
		// t.Logf("file %s", fp)
		var pkgFound bool
		var pkgName string
		fh, _ := os.Open(fp)
		defer fh.Close()
		scanner := bufio.NewScanner(fh)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "package ") {
				pkgFound = true
				pkgName = strings.Split(line, " ")[1]
				// t.Logf("package %s", pkgName)
				continue
			}
			if !pkgFound {
				continue
			}
			if strings.HasPrefix(line, "type") && strings.Contains(line, "struct") {
				structName := strings.Split(line, " ")[1]
				// t.Logf("%s.%s", pkgName, structName)
				r, _ := utf8.DecodeRuneInString(structName)
				if unicode.IsUpper(r) {
					structMap[pkgName+"."+structName] = false
				}
			}

			//fmt.Println(scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			t.Errorf("failed reading %q: %v", fp, err)
		}
	}

	fp := "../../internal/tag/tag_test.go"
	fh, _ := os.Open(fp)
	defer fh.Close()
	scanner := bufio.NewScanner(fh)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		for k := range structMap {
			if strings.Contains(line, k+"{}") {
				structMap[k] = true
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Errorf("failed reading %q: %v", fp, err)
	}

	if len(structMap) > 0 {
		var msgs []string
		for k, v := range structMap {
			if v == false {
				t.Logf("Found struct %s", k)
				msgs = append(msgs, fmt.Sprintf("{\nname: \"test %s struct\",\nentry: &%s{},\nopts: &Options{},\n},", k, k))
			}
		}
		if len(msgs) > 0 {
			t.Logf("Add the following tests:\n" + strings.Join(msgs, "\n"))
		}
	}

}
