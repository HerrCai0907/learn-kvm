(module
  (func (param i32 i32) (result i32)
    local.get 0
    i32.const 0
    i32.div_s
  )
  (export "add" (func 0))
)
