OS := $(shell uname)
NS = peterxu
VERSION ?= latest
REPO = docker-xrtc

JANUS_IP ?= "127.0.0.1"
UMS_IP ?= "127.0.0.1"

all: build

build:
	@PKG_CONFIG_PATH=/usr/local/lib/pkgconfig go build -ldflags "-s -w"

clean:
	@go clean

run: build
	@go run main.go

docker: build
	docker build -t $(NS)/$(REPO):$(VERSION) -f testing/Dockerfile .

deploy: 
	docker-compose -f testing/docker-compose up -d

docker-build:
	@test "$(OS)" = "Linux"
	@(cp -rf /usr/local/include testing/include)
	@(cp -rf /usr/local/lib testing/lib)
	@(docker build -t $(NS)/$(REPO)-build:$(VERSION) -f testing/Dockerfile.build testing)
	@(rm -rf testing/include testing/lib)

docker-mac:
	@docker run -v $(GOPATH):/gopath -v $(shell pwd):/gobuild -it --rm peterxu/docker-xrtc-build make
	@mv -f gobuild xrtc.gen
	@docker build -t $(NS)/$(REPO):cross -f testing/Dockerfile.cross .

deploy-mac:
	@export janus_api=$(JANUS_IP) && export ums_api=$(UMS_IP) && \
	docker-compose -f testing/docker-compose.cross.yml up -d
	@docker logs -f xrtc-proxy

