.PHONY: build test deb clean

build:
	cargo build --release --manifest-path engine-rust/Cargo.toml
	mkdir -p build
	go build -trimpath -ldflags="-s -w" -o build/proxygo-proxy ./cmd/proxygo
	go build -trimpath -ldflags="-s -w" -o build/proxygo-cli ./cmd/proxygo-cli

test:
	go test ./...
	./audit_proxygo.sh

deb: build
	mkdir -p dist
	nfpm package --config packaging/nfpm.yaml --packager deb --target dist/

clean:
	rm -rf build dist
