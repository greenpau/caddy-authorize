// Copyright 2020 Paul Greenberg (greenpau@outlook.com)

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
	configFile := "assets/conf/config.json"
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

	tester.InitServer(rawConfig, "json")
	tester.AssertGetResponse(baseURL+"/version", 200, "1.0.0")

	time.Sleep(1 * time.Second)
}

func TestPluginReload(t *testing.T) {
	tester := caddytest.NewTester(t)
	baseURL := "https://127.0.0.1:3443"
	configFile := "assets/conf/config_reloaded.json"
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

	tester.InitServer(rawConfig, "json")
	tester.AssertGetResponse(baseURL+"/version", 200, "1.0.0")

	time.Sleep(1 * time.Second)
}
