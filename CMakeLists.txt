cmake_minimum_required(VERSION 3.15)
project(wasm-kvm)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_subdirectory(wasm-compiler)
add_subdirectory(src)
