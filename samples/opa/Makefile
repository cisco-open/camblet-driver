opa-bundle:
	opa build -t wasm -e "xdp/allow" xdp.rego -o bundle.tar.gz
	tar zxvf bundle.tar.gz /policy.wasm

opa-test:
	opa test *.rego -v
