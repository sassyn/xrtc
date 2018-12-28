all: build

build:
	@PKG_CONFIG_PATH="/usr/local/lib/pkgconfig" go build

clean:
	@go clean

run: build
	go run main.go
