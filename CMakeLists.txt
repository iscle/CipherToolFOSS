cmake_minimum_required(VERSION 3.16)
project(CipherToolFOSS C)

set(CMAKE_C_STANDARD 99)

include_directories(asf/asf_inc)

add_executable(CipherToolFOSS
        asf/core/alg_aes_export.c
        asf/core/alg_aes_legacy.c
        asf/core/alg_aes_so.c
        main.c
        )
