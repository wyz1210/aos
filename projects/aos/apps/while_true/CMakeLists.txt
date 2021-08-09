cmake_minimum_required(VERSION 3.7.2)

project(while_true C)

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -u __vsyscall_ptr")

# list all source files here
add_executable(while_true EXCLUDE_FROM_ALL src/while_true.c)
# list libraries to link binary against
target_link_libraries(while_true sel4runtime muslc sel4 sosapi)

# warn about everything
add_compile_options(-Wall -Werror -W -Wextra)

add_app(while_true)