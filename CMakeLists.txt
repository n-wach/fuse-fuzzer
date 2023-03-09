# be sure your target library (named example-fuse-lib here) has been built with the following flags:
target_link_options(example-fuse-lib PUBLIC -fsanitize=fuzzer-no-link)
target_compile_options(example-fuse-lib PUBLIC -fsanitize=fuzzer-no-link)

add_library(harness harness.c ../src/snaffs.h)
target_compile_options(harness PUBLIC -fsanitize=fuzzer)
target_link_options(harness PUBLIC -fsanitize=fuzzer)
target_link_libraries(harness example-fuse-lib)

find_package(Protobuf REQUIRED)
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS commands.proto)
include_directories(${Protobuf_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(/usr/local/include/libprotobuf-mutator)

include(FetchContent)
FetchContent_Declare(
        protobuf-mutator-libfuzzer
        GIT_REPOSITORY https://github.com/google/libprotobuf-mutator.git
        GIT_TAG        master
)
FetchContent_MakeAvailable(protobuf-mutator-libfuzzer)

add_executable(fuzzer fuzzer.cpp ${PROTO_SRCS} ${PROTO_HDRS})
target_compile_options(fuzzer PUBLIC -fsanitize=fuzzer)
target_link_options(fuzzer PUBLIC -fsanitize=fuzzer)
target_link_libraries(fuzzer protobuf::libprotobuf protobuf-mutator-libfuzzer harness)

# for coverage reports, build another version of your library with coverage flags:
target_link_options(example-fuse-lib-cov PUBLIC -fsanitize=fuzzer -fprofile-instr-generate -fcoverage-mapping)
target_compile_options(example-fuse-lib-cov PUBLIC -fsanitize=fuzzer -fprofile-instr-generate -fcoverage-mapping)

# and another version of the harness:
add_library(harness-cov harness.c ../src/snaffs.h)
target_compile_options(harness-cov PUBLIC -fsanitize=fuzzer -fprofile-instr-generate -fcoverage-mapping)
target_link_options(harness-cov PUBLIC -fsanitize=fuzzer -fprofile-instr-generate -fcoverage-mapping)
target_link_libraries(harness-cov example-fuse-lib-cov)

# and another version of the fuzzer for coverage reports:
add_executable(fuzzer-cov fuzzer.cpp ${PROTO_SRCS} ${PROTO_HDRS})
target_compile_options(fuzzer-cov PUBLIC -fsanitize=fuzzer)
target_link_options(fuzzer-cov PUBLIC -fsanitize=fuzzer)
target_link_libraries(fuzzer-cov protobuf::libprotobuf protobuf-mutator-libfuzzer harness-cov)
