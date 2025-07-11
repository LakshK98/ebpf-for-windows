// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_platform.h"
#include "ebpf_tracelog.h"

#include <bcrypt.h>
#pragma comment(lib, "bcrypt")

// This file contains the wrapper around the crypto API.

typedef struct _ebpf_cryptographic_hash
{
    BCRYPT_ALG_HANDLE algorithm_handle;
    BCRYPT_HASH_HANDLE hash_handle;
} ebpf_cryptographic_hash_t;

_Must_inspect_result_ ebpf_result_t
ebpf_cryptographic_hash_create(_In_ const cxplat_utf8_string_t* algorithm, _Outptr_ ebpf_cryptographic_hash_t** hash)
{
    ebpf_result_t result;
    NTSTATUS nt_status;
    wchar_t* algorithm_unicode_string = NULL;
    ebpf_cryptographic_hash_t* local_hash =
        (ebpf_cryptographic_hash_t*)ebpf_allocate(sizeof(ebpf_cryptographic_hash_t));
    if (local_hash == NULL) {
        result = EBPF_NO_MEMORY;
        goto Done;
    }

    memset(local_hash, 0, sizeof(ebpf_cryptographic_hash_t));
    result = ebpf_utf8_string_to_unicode(algorithm, &algorithm_unicode_string);
    if (result != EBPF_SUCCESS) {
        goto Done;
    }

    nt_status = BCryptOpenAlgorithmProvider(&local_hash->algorithm_handle, algorithm_unicode_string, NULL, 0);
    if (!NT_SUCCESS(nt_status)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    nt_status = BCryptCreateHash(local_hash->algorithm_handle, &local_hash->hash_handle, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(nt_status)) {
        result = EBPF_INVALID_ARGUMENT;
        goto Done;
    }

    result = EBPF_SUCCESS;
    *hash = local_hash;
    local_hash = NULL;
Done:
    ebpf_free(algorithm_unicode_string);
    ebpf_cryptographic_hash_destroy(local_hash);
    local_hash = NULL;
    return result;
}

// SAL annotation must be _In_opt_ as this function looks inside the structure to free entries.
void
ebpf_cryptographic_hash_destroy(_In_opt_ _Frees_ptr_opt_ ebpf_cryptographic_hash_t* hash)
{
    if (hash) {
        if (hash->hash_handle) {
            BCryptDestroyHash(hash->hash_handle);
        }
        if (hash->algorithm_handle) {
            BCryptCloseAlgorithmProvider(hash->algorithm_handle, 0);
        }
        ebpf_free(hash);
    }
}

_Must_inspect_result_ ebpf_result_t
ebpf_cryptographic_hash_append(
    _Inout_ ebpf_cryptographic_hash_t* hash, _In_reads_bytes_(length) const uint8_t* buffer, size_t length)
{
    NTSTATUS nt_status;

    nt_status = BCryptHashData(hash->hash_handle, (uint8_t*)buffer, (unsigned long)length, 0);
    if (!NT_SUCCESS(nt_status)) {
        return EBPF_INVALID_ARGUMENT;
    }
    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_cryptographic_hash_get_hash(
    _Inout_ ebpf_cryptographic_hash_t* hash,
    _Out_writes_to_(input_length, *output_length) uint8_t* buffer,
    size_t input_length,
    _Out_ size_t* output_length)
{
    NTSTATUS nt_status;
    unsigned long property_length;
    nt_status = BCryptGetProperty(
        hash->hash_handle, BCRYPT_HASH_LENGTH, (PUCHAR)output_length, sizeof(*output_length), &property_length, 0);
    if (!NT_SUCCESS(nt_status)) {
        return EBPF_INVALID_ARGUMENT;
    }

    if ((*output_length > input_length) || (*output_length > UINT32_MAX)) {
        return EBPF_INSUFFICIENT_BUFFER;
    }

    nt_status = BCryptFinishHash(hash->hash_handle, buffer, (unsigned long)*output_length, 0);
    if (!NT_SUCCESS(nt_status)) {
        return EBPF_INVALID_ARGUMENT;
    }

    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_cryptographic_hash_get_hash_length(_In_ const ebpf_cryptographic_hash_t* hash, _Out_ size_t* length)
{
    NTSTATUS nt_status;
    unsigned long property_length;
    nt_status =
        BCryptGetProperty(hash->hash_handle, BCRYPT_HASH_LENGTH, (PUCHAR)length, sizeof(*length), &property_length, 0);
    if (!NT_SUCCESS(nt_status)) {
        return EBPF_INVALID_ARGUMENT;
    }
    return EBPF_SUCCESS;
}

_Must_inspect_result_ ebpf_result_t
ebpf_hash_file_contents(
    _In_ const cxplat_utf8_string_t* file_name,
    _In_ const cxplat_utf8_string_t* algorithm,
    _Out_writes_bytes_(length) uint8_t* buffer,
    size_t length,
    _Out_ size_t* output_length)
{
    EBPF_LOG_ENTRY();
    ebpf_result_t result;
    ebpf_cryptographic_hash_t* hash = NULL;
    HANDLE file_handle = NULL;
    HANDLE mapping_handle = NULL;
    void* base_address = NULL;
    size_t size = 0;

    result = ebpf_cryptographic_hash_create(algorithm, &hash);
    if (result != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_BASE, "Failed to create hash object");
        goto Done;
    }

    result = ebpf_open_readonly_file_mapping(file_name, &file_handle, &mapping_handle, &base_address, &size);
    if (result != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_BASE, "Failed to open file mapping");
        goto Done;
    }

    if (size == 0) {
        EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_BASE, "File size is zero");
        result = EBPF_FILE_NOT_FOUND;
        goto Done;
    }

    // Append the file content to the hash.
    result = ebpf_cryptographic_hash_append(hash, (const uint8_t*)base_address, size);

    if (result != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE(
            EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_BASE, "Failed to append file content to hash");
        goto Done;
    }

    // Get the hash value.
    result = ebpf_cryptographic_hash_get_hash(hash, buffer, length, output_length);
    if (result != EBPF_SUCCESS) {
        EBPF_LOG_MESSAGE(EBPF_TRACELOG_LEVEL_ERROR, EBPF_TRACELOG_KEYWORD_BASE, "Failed to get hash value");
        goto Done;
    }

Done:
    ebpf_cryptographic_hash_destroy(hash);
    hash = NULL;

    ebpf_close_file_mapping(file_handle, mapping_handle, base_address);

    EBPF_RETURN_RESULT(result);
}
