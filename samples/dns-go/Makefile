go-sample:
	tinygo build -o dns-go.wasm \
	-target=wasm \
	-gc=leaking -panic=trap -scheduler=none \
	-opt=z main.go
