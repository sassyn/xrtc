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

docker: build
	docker build -t $(NS)/$(REPO):$(VERSION) .

deploy: 
	docker-compose up -d

docker-build:
	@cp -rf /usr/local/include testing/include
	@cp -rf /usr/local/lib testing/lib
	@(docker build -t $(NS)/$(REPO)-build:$(VERSION) testing)
	@rm -rf testing/include testing/lib

docker-gen:
	@docker run -v $(GOPATH):/gopath -v $(shell pwd):/gobuild -it --rm peterxu/docker-xrtc-build make
	@mv -f gobuild xrtc.gen

