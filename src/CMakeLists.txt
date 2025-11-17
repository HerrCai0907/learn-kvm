aux_source_directory(. SRC_FILES)
add_executable(wasm-kvm ${SRC_FILES})
target_link_libraries(wasm-kvm vb_libWasmModule)

