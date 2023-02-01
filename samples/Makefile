rust-sample:
	cargo build --release
	cp target/wasm32-unknown-unknown/release/dns-rust.wasm .

go-sample:
	tinygo build -o dns-go.wasm \
	-target=wasm -wasm-abi=generic \
	-gc=leaking -panic=trap -scheduler=none \
	-opt=z main.go
