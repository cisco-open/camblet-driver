(module
  ;; _debug is exported by the wasm3 runtime
  (import "env" "_debug" (func $printf (param i32 i32) (result i32))) 
  (memory $0 1)
  (data (i32.const 0) "Hello")
  (func (export "main") (param i32 i32) (result i32)
      i32.const 0  ;; pass offset 0 to printf
      i32.const 5  ;; pass length 5 to printf
      (call $printf)))
