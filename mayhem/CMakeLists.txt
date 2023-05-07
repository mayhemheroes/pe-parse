add_executable(fuzz_pe fuzz_lib.cpp)

target_compile_options(fuzz_pe PRIVATE -fsanitize=fuzzer,address,undefined)
target_link_options(fuzz_pe PRIVATE -fsanitize=fuzzer,address,undefined)

target_link_libraries(fuzz_pe PRIVATE pe-parse::pe-parse)
