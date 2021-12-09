.PHONY: test ctest covdir coverage docs linter qtest clean dep release templates info license
PLUGIN_NAME="caddy-authorize"
REPO_BASE="github.com/greenpau/caddy-authorize"
PLUGIN_VERSION:=$(shell cat VERSION | head -1)
GIT_COMMIT:=$(shell git describe --dirty --always)
GIT_BRANCH:=$(shell git rev-parse --abbrev-ref HEAD -- | head -1)
LATEST_GIT_COMMIT:=$(shell git log --format="%H" -n 1 | head -1)
BUILD_USER:=$(shell whoami)
BUILD_DATE:=$(shell date +"%Y-%m-%d")
BUILD_DIR:=$(shell pwd)
VERBOSE:=-v
ifdef TEST
	TEST:="-run ${TEST}"
endif
CADDY_VERSION="v2.4.3"

all: build

build: info license
	@mkdir -p bin/
	@rm -rf ./bin/caddy
	@rm -rf ../xcaddy-$(PLUGIN_NAME)/*
	@mkdir -p ../xcaddy-$(PLUGIN_NAME) && cd ../xcaddy-$(PLUGIN_NAME) && \
		xcaddy build $(CADDY_VERSION) --output ../$(PLUGIN_NAME)/bin/caddy \
		--with github.com/greenpau/caddy-authorize@$(LATEST_GIT_COMMIT)=$(BUILD_DIR) \
		--with github.com/greenpau/caddy-auth-portal@latest=$(BUILD_DIR)/../caddy-auth-portal

info:
	@echo "Version: $(PLUGIN_VERSION), Branch: $(GIT_BRANCH), Revision: $(GIT_COMMIT)"
	@echo "Build on $(BUILD_DATE) by $(BUILD_USER)"

linter:
	@echo "Running lint checks"
	@golint -set_exit_status ./... 
	@echo "PASS: linter"

test: covdir linter
	@echo "Running tests"
	@go test $(VERBOSE) -coverprofile=.coverage/coverage.out ./...
	@echo "PASS: test"

ctest: covdir linter
	@time richgo test $(VERBOSE) $(TEST) -coverprofile=.coverage/coverage.out ./...

covdir:
	@echo "Creating .coverage/ directory"
	@mkdir -p .coverage

coverage:
	@go tool cover -html=.coverage/coverage.out -o .coverage/coverage.html
	@go test -covermode=count -coverprofile=.coverage/coverage.out ./...
	@go tool cover -func=.coverage/coverage.out | grep -v "100.0"

docs:
	@versioned -toc
	@mkdir -p .doc
	@go doc -all > .doc/index.txt

clean:
	@rm -rf .doc
	@rm -rf .coverage
	@rm -rf bin/

qtest: covdir
	@echo "Perform quick tests ..."
	@#time richgo test -v -run TestPlugin ./*.go
	@#time richgo test -v -run TestTokenProviderConfig ./*.go
	@#time richgo test -v -run TestTokenCache ./*.go
	@#time richgo test -v -run TestNewGrantor ./*.go
	@#time richgo test -v -run TestAppMetadataAuthorizationRoles ./pkg/user/*.go
	@#time richgo test -v -run TestRealmAccessRoles ./pkg/user/*.go
	@#time richgo test -v -run TestGrantValidate ./pkg/auth/*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out ./pkg/user/*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out ./pkg/authz/*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out ./pkg/cache/*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out ./pkg/kms/*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out ./pkg/acl/*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out ./pkg/testutils/*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out ./pkg/validator/*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestAuthorize ./pkg/validator/*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestNewClaimsFromMap ./pkg/user/*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run MatchPathBasedACL ./pkg/acl/*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestNewAccessList ./pkg/acl/*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestEvalAclRule ./pkg/acl/*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run ReadUserClaims ./pkg/user/*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run AuthorizationSources ./pkg/validator/*.go
	@#time richgo test -v -run TestGetSignedToken ./pkg/user/*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestNewUserClaimsFromMap ./pkg/user/*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestTokenValidity ./pkg/user/*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out ./pkg/user/*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestLoadKeyManager ./pkg/kms/*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run ParseCryptoKeyConfigs ./pkg/kms/*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestParseCryptoKeyConfigs ./pkg/kms/*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestValidateCryptoKeyConfig ./pkg/kms/*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestGetKeysFromConfig ./pkg/kms/*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestKeystoreOperators ./pkg/kms/*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestCryptoKeyStoreAutoGenerate ./pkg/kms/*.go
	@time richgo test -v -coverprofile=.coverage/coverage.out -run TestCaddyfile ./*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run TestParser ./*.go
	@#time richgo test -v -coverprofile=.coverage/coverage.out -run Test* ./pkg/utils/cfgutils/*.go
	@#time richgo test -v ./internal/tag/*.go
	@go tool cover -html=.coverage/coverage.out -o .coverage/coverage.html
	@go tool cover -func=.coverage/coverage.out | grep -v "100.0"

qdoc:
	@#go doc -all $(REPO_BASE)/pkg/acl
	@#go doc -all $(REPO_BASE)/pkg/validator
	@go doc -all $(REPO_BASE)/pkg/kms

dep:
	@echo "Making dependencies check ..."
	@golint || go get -u golang.org/x/lint/golint
	@go get -u github.com/kyoh86/richgo
	@go get -u github.com/caddyserver/xcaddy/cmd/xcaddy
	@pip3 install Markdown --user
	@pip3 install markdownify --user
	@versioned || go get -u github.com/greenpau/versioned/cmd/versioned@v1.0.26

license:
	@versioned || go get -u github.com/greenpau/versioned/cmd/versioned@v1.0.26
	@for f in `find ./ -type f -name '*.go'`; do versioned -addlicense -copyright="Paul Greenberg greenpau@outlook.com" -year=2020 -filepath=$$f; done

mod:
	@go mod tidy
	@go mod verify

release:
	@echo "Making release"
	@if [ $(GIT_BRANCH) != "main" ]; then echo "cannot release to non-main branch $(GIT_BRANCH)" && false; fi
	@git diff-index --quiet HEAD -- || ( echo "git directory is dirty, commit changes first" && false )
	@versioned -patch
	@echo "Patched version"
	@git add VERSION
	@git commit -m "released v`cat VERSION | head -1`"
	@git tag -a v`cat VERSION | head -1` -m "v`cat VERSION | head -1`"
	@git push
	@git push --tags
	@echo "If necessary, run the following commands:"
	@echo "  git push --delete origin v$(PLUGIN_VERSION)"
	@echo "  git tag --delete v$(PLUGIN_VERSION)"
