GOPRIVATE="gitlab.lrz.de"
GO_SOURCES = $(shell find . -name '*.go')
GO_CH_SOURCES = $(shell find ./scanner/cmd/createch -name '*.go')

PROJECT_NAME := "goscanner"
PKG := "github.com/tumi8/$(PROJECT_NAME)"
PKG_LIST := $(shell go list ${PKG}/... | grep -v /vendor/)

VERSION = "unreleased"

GITDESCRIBE=$(shell git describe --always --dirty)
GITUNTRACKED=$(shell test -n "$$(git ls-files --others --exclude-standard)" && printf %s -untracked)
GITBRANCH=$(shell git rev-parse --abbrev-ref HEAD)

LDFLAGS=-ldflags "-X main.GitBranch=$(GITBRANCH) -X main.GitHash=$(GITDESCRIBE)$(GITUNTRACKED)"

.PHONY: all lint test race goget random-chs

goscanner: $(GO_SOURCES)
	go build -mod readonly $(LDFLAGS) -o $@ main.go

client-hellos: goscanner
	./goscanner create-ch --out $@ -c jarm
	./goscanner create-ch --out $@ -c custom
	touch $@

random-chs: goscanner
	./goscanner create-ch --out ./client-hellos -c random --num-random 1000 --tmp ./tmp

lint: ## Lint the files
	go get -u golang.org/x/lint
	golint -set_exit_status ${PKG_LIST}

test: ## Run unittests
	go test -short ${PKG_LIST} -coverprofile .testCoverage.txt

race: goget ## Run data race detector
	go test -race -short ${PKG_LIST}

goget:
	go get

goscanner-linux-amd64: $(GO_SOURCES) go.sum
	env GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o goscanner-linux-amd64

all: goget goscanner client-hellos
