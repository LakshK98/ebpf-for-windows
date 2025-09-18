// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "api_internal.h"
#include "api_test.h"
#include "bpf/libbpf.h"
#include "catch_wrapper.hpp"
#include "ebpf_structs.h"
#include "service_helper.h"

#define SAMPLE_PROGRAM_COUNT 1
#define BIND_MONITOR_PROGRAM_COUNT 1

#define SAMPLE_MAP_COUNT 1
#define BIND_MONITOR_MAP_COUNT 3

#if !defined(CONFIG_BPF_JIT_DISABLED) || !defined(CONFIG_BPF_INTERPRETER_DISABLED)
#define EBPF_SERVICE_BINARY_NAME L"ebpfsvc.exe"
#define EBPF_SERVICE_NAME L"ebpfsvc"

inline service_install_helper
    _ebpf_service_helper(EBPF_SERVICE_NAME, EBPF_SERVICE_BINARY_NAME, SERVICE_WIN32_OWN_PROCESS);
#endif

typedef struct _audit_entry
{
    uint64_t logon_id;
    int32_t is_admin;
} audit_entry_t;

#if defined(CONFIG_BPF_JIT_DISABLED)
#define JIT_LOAD_RESULT -ENOTSUP
#else
#define JIT_LOAD_RESULT 0

int32_t
get_expected_jit_result(int32_t expected_result);
#endif

inline  _Success_(return == 0) int _program_load_helper(
    _In_z_ const char* file_name,
    bpf_prog_type prog_type,
    ebpf_execution_type_t execution_type,
    _Outptr_ struct bpf_object** object,
    _Out_ fd_t* program_fd) // File descriptor of first program in the object.
{
    *program_fd = ebpf_fd_invalid;
    *object = nullptr;
    struct bpf_object* new_object = bpf_object__open(file_name);
    if (new_object == nullptr) {
        return -EINVAL;
    }

    REQUIRE(ebpf_object_set_execution_type(new_object, execution_type) == EBPF_SUCCESS);

    struct bpf_program* program = bpf_object__next_program(new_object, nullptr);

    if (prog_type != BPF_PROG_TYPE_UNSPEC) {
        bpf_program__set_type(program, prog_type);
    }

    int error = bpf_object__load(new_object);
    if (error < 0) {
        bpf_object__close(new_object);
        return error;
    }

    if (program != nullptr) {
        *program_fd = bpf_program__fd(program);
    }
    *object = new_object;
    return 0;
}

inline void
_test_program_next_previous(const char* file_name, int expected_program_count)
{
    int result;
    struct bpf_object* object = nullptr;
    fd_t program_fd;
    int program_count = 0;
    struct bpf_program* previous = nullptr;
    struct bpf_program* next = nullptr;
    result = _program_load_helper(file_name, BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_ANY, &object, &program_fd);
    REQUIRE(result == 0);

    next = bpf_object__next_program(object, previous);
    while (next != nullptr) {
        program_count++;
        previous = next;
        next = bpf_object__next_program(object, previous);
    }
    REQUIRE(program_count == expected_program_count);

    program_count = 0;
    previous = next = nullptr;

    previous = bpf_object__prev_program(object, next);
    while (previous != nullptr) {
        program_count++;
        next = previous;
        previous = bpf_object__prev_program(object, next);
    }
    REQUIRE(program_count == expected_program_count);

    bpf_object__close(object);
}

inline void
_test_map_next_previous(const char* file_name, int expected_map_count)
{
    int result;
    struct bpf_object* object = nullptr;
    fd_t program_fd;
    int map_count = 0;
    struct bpf_map* previous = nullptr;
    struct bpf_map* next = nullptr;
    result = _program_load_helper(file_name, BPF_PROG_TYPE_UNSPEC, EBPF_EXECUTION_ANY, &object, &program_fd);
    REQUIRE(result == 0);

    next = bpf_object__next_map(object, previous);
    while (next != nullptr) {
        map_count++;
        previous = next;
        next = bpf_object__next_map(object, previous);
    }
    REQUIRE(map_count == expected_map_count);

    map_count = 0;
    previous = next = nullptr;

    previous = bpf_object__prev_map(object, next);
    while (previous != nullptr) {
        map_count++;
        next = previous;
        previous = bpf_object__prev_map(object, next);
    }
    REQUIRE(map_count == expected_map_count);

    bpf_object__close(object);
}

void
perform_socket_bind(const uint16_t test_port, bool expect_success);

void
tailcall_load_test(_In_z_ const char* file_name);

void
bpf_user_helpers_test(ebpf_execution_type_t execution_type);