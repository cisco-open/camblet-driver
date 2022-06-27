go-sample:
	tinygo build -o dns-go.wasm \
	-target=wasm -wasm-abi=generic \
	-gc=leaking -panic=trap -scheduler=none \
	-opt=z main.go

rust-sample:
	cargo build --target wasm32-unknown-unknown --release
