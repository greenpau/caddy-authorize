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

package jwt

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestPlugin(t *testing.T) {

	tester := caddytest.NewTester(t)
	baseURL := "https://127.0.0.1:3443"
	configFile := "assets/conf/Caddyfile"
	configContent, err := ioutil.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load configuration file %s: %s", configFile, err)
	}
	rawConfig := string(configContent)

	/*
		curDir, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}

		rawConfig = strings.ReplaceAll(rawConfig, "testdata", curDir+"/testdata")
	*/

	tester.InitServer(rawConfig, "caddyfile")
	tester.AssertGetResponse(baseURL+"/version", 200, "1.0.0")

	time.Sleep(1 * time.Second)
}

func TestPluginReload(t *testing.T) {
	tester := caddytest.NewTester(t)
	baseURL := "https://127.0.0.1:3443"
	configFile := "assets/conf/v2/Caddyfile"
	configContent, err := ioutil.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load configuration file %s: %s", configFile, err)
	}
	rawConfig := string(configContent)

	curDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	rawConfig = strings.ReplaceAll(rawConfig, "testdata", curDir+"/testdata")

	tester.InitServer(rawConfig, "caddyfile")
	tester.AssertGetResponse(baseURL+"/version", 200, "1.0.0")

	time.Sleep(1 * time.Second)
}
