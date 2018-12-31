NS = peterxu
VERSION ?= latest
REPO = docker-xrtc

all: build

build:
	@PKG_CONFIG_PATH=/usr/local/lib/pkgconfig go build -ldflags "-s -w"

clean:
	@go clean

run: build
	@go run main.go

docker:
	docker build -t $(NS)/$(REPO):$(VERSION) .
