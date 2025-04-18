// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

/*++

Abstract:

   This file implements the classifyFn, notifyFn, and flowDeleteFn callouts
   functions for:
   Layer 2 network receive
   Resource Acquire
   Resource Release

Environment:

    Kernel mode

--*/

#include "net_ebpf_ext.h"
#include "net_ebpf_ext_bind.h"
#include "net_ebpf_ext_sock_addr.h"
#include "net_ebpf_ext_sock_ops.h"
#include "net_ebpf_ext_xdp.h"

#define SECONDSTO100NS(x) ((x)*10000000)
#define SUBLAYER_WEIGHT_MAXIMUM 0xFFFF

// Globals.
NDIS_HANDLE _net_ebpf_ext_ndis_handle = NULL;
NDIS_HANDLE _net_ebpf_ext_nbl_pool_handle = NULL;
HANDLE _net_ebpf_ext_l2_injection_handle = NULL;

static bool _net_ebpf_xdp_providers_registered = false;
static bool _net_ebpf_bind_providers_registered = false;
static bool _net_ebpf_sock_addr_providers_registered = false;
static bool _net_ebpf_sock_ops_providers_registered = false;

static net_ebpf_ext_sublayer_info_t _net_ebpf_ext_sublayers[] = {
    {&EBPF_DEFAULT_SUBLAYER, L"EBPF Sub-Layer", L"Sub-Layer for use by eBPF callouts", 0, SUBLAYER_WEIGHT_MAXIMUM},
    {&EBPF_HOOK_CGROUP_CONNECT_V4_SUBLAYER,
     L"EBPF CGroup Connect V4 Sub-Layer",
     L"Sub-Layer for use by eBPF connect redirect callouts",
     0,
     SUBLAYER_WEIGHT_MAXIMUM},
    {&EBPF_HOOK_CGROUP_CONNECT_V6_SUBLAYER,
     L"EBPF CGroup Connect V6 Sub-Layer",
     L"Sub-Layer for use by eBPF connect redirect callouts",
     0,
     SUBLAYER_WEIGHT_MAXIMUM}};

// Global object used to store state for cleanup.
static net_ebpf_extension_wfp_cleanup_state_t _net_ebpf_ext_wfp_cleanup_state = {0};

static void
_net_ebpf_ext_flow_delete(uint16_t layer_id, uint32_t callout_id, uint64_t flow_context);

NTSTATUS
net_ebpf_ext_filter_change_notify(
    FWPS_CALLOUT_NOTIFY_TYPE callout_notification_type, _In_ const GUID* filter_key, _Inout_ FWPS_FILTER* filter);

typedef struct _net_ebpf_ext_wfp_callout_state
{
    const GUID* callout_guid;
    const GUID* layer_guid;
    FWPS_CALLOUT_CLASSIFY_FN classify_fn;
    FWPS_CALLOUT_NOTIFY_FN notify_fn;
    FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN delete_fn;
    wchar_t* name;
    wchar_t* description;
    FWP_ACTION_TYPE filter_action_type;
    uint32_t assigned_callout_id;
} net_ebpf_ext_wfp_callout_state_t;

static net_ebpf_ext_wfp_callout_state_t _net_ebpf_ext_wfp_callout_states[] = {
    // EBPF_HOOK_OUTBOUND_L2
    {
        &EBPF_HOOK_OUTBOUND_L2_CALLOUT,
        &FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE,
        net_ebpf_ext_layer_2_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"L2 Outbound",
        L"L2 Outbound Callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_INBOUND_L2
    {
        &EBPF_HOOK_INBOUND_L2_CALLOUT,
        &FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE,
        net_ebpf_ext_layer_2_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"L2 Inbound",
        L"L2 Inbound Callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_RESOURCE_ALLOC_V4
    {
        &EBPF_HOOK_ALE_RESOURCE_ALLOC_V4_CALLOUT,
        &FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
        net_ebpf_ext_resource_allocation_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"Resource Allocation v4",
        L"Resource Allocation v4 callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_RESOURCE_RELEASE_V4
    {
        &EBPF_HOOK_ALE_RESOURCE_RELEASE_V4_CALLOUT,
        &FWPM_LAYER_ALE_RESOURCE_RELEASE_V4,
        net_ebpf_ext_resource_release_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"Resource Release v4",
        L"Resource Release v4 callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_RESOURCE_ALLOC_V6
    {
        &EBPF_HOOK_ALE_RESOURCE_ALLOC_V6_CALLOUT,
        &FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6,
        net_ebpf_ext_resource_allocation_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"Resource Allocation v6",
        L"Resource Allocation v6 callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_RESOURCE_RELEASE_V6
    {
        &EBPF_HOOK_ALE_RESOURCE_RELEASE_V6_CALLOUT,
        &FWPM_LAYER_ALE_RESOURCE_RELEASE_V6,
        net_ebpf_ext_resource_release_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"Resource Release eBPF Callout v6",
        L"Resource Release callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_AUTH_CONNECT_V4
    {
        &EBPF_HOOK_ALE_AUTH_CONNECT_V4_CALLOUT,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        net_ebpf_extension_sock_addr_authorize_connection_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"ALE Authorize Connect eBPF Callout v4",
        L"ALE Authorize Connect callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_AUTH_CONNECT_V6
    {
        &EBPF_HOOK_ALE_AUTH_CONNECT_V6_CALLOUT,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        net_ebpf_extension_sock_addr_authorize_connection_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"ALE Authorize Connect eBPF Callout v6",
        L"ALE Authorize Connect callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V4
    {
        &EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V4_CALLOUT,
        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        net_ebpf_extension_sock_addr_authorize_recv_accept_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"ALE Authorize Receive or Accept eBPF Callout v4",
        L"ALE Authorize Receive or Accept callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V6
    {
        &EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V6_CALLOUT,
        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        net_ebpf_extension_sock_addr_authorize_recv_accept_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"ALE Authorize Receive or Accept eBPF Callout v6",
        L"ALE Authorize Receive or Accept callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_CONNECT_REDIRECT_V4
    {
        &EBPF_HOOK_ALE_CONNECT_REDIRECT_V4_CALLOUT,
        &FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
        net_ebpf_extension_sock_addr_redirect_connection_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"ALE Connect Redirect eBPF Callout v4",
        L"ALE Connect Redirect callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_CONNECT_REDIRECT_V6
    {
        &EBPF_HOOK_ALE_CONNECT_REDIRECT_V6_CALLOUT,
        &FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
        net_ebpf_extension_sock_addr_redirect_connection_classify,
        net_ebpf_ext_filter_change_notify,
        _net_ebpf_ext_flow_delete,
        L"ALE Connect Redirect eBPF Callout v6",
        L"ALE Connect Redirect callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_FLOW_ESTABLISHED_V4
    {
        &EBPF_HOOK_ALE_FLOW_ESTABLISHED_V4_CALLOUT,
        &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
        net_ebpf_extension_sock_ops_flow_established_classify,
        net_ebpf_ext_filter_change_notify,
        net_ebpf_extension_sock_ops_flow_delete,
        L"ALE Flow Established Callout v4",
        L"ALE Flow Established callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    },
    // EBPF_HOOK_ALE_FLOW_ESTABLISHED_V6
    {
        &EBPF_HOOK_ALE_FLOW_ESTABLISHED_V6_CALLOUT,
        &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
        net_ebpf_extension_sock_ops_flow_established_classify,
        net_ebpf_ext_filter_change_notify,
        net_ebpf_extension_sock_ops_flow_delete,
        L"ALE Flow Established Callout v4",
        L"ALE Flow Established callout for eBPF",
        FWP_ACTION_CALLOUT_TERMINATING,
    }};

// WFP globals
static HANDLE _fwp_engine_handle;

//
// WFP component management related utility functions.
//

_Must_inspect_result_ ebpf_result_t
net_ebpf_extension_wfp_filter_context_create(
    size_t filter_context_size,
    _In_ const net_ebpf_extension_hook_client_t* client_context,
    _In_ const net_ebpf_extension_hook_provider_t* provider_context,
    _Outptr_ net_ebpf_extension_wfp_filter_context_t** filter_context)
{
    NTSTATUS status = STATUS_SUCCESS;
    ebpf_result_t result = EBPF_SUCCESS;
    net_ebpf_extension_wfp_filter_context_t* local_filter_context = NULL;
    uint32_t client_context_count_max = NET_EBPF_EXT_MAX_CLIENTS_PER_HOOK_SINGLE_ATTACH;

    NET_EBPF_EXT_LOG_ENTRY();

    *filter_context = NULL;

    if (net_ebpf_extension_hook_provider_get_attach_capability(provider_context) ==
        ATTACH_CAPABILITY_MULTI_ATTACH_WITH_WILDCARD) {
        client_context_count_max = NET_EBPF_EXT_MAX_CLIENTS_PER_HOOK_MULTI_ATTACH;
    }

    // Allocate buffer for WFP filter context.
    local_filter_context = (net_ebpf_extension_wfp_filter_context_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, filter_context_size, NET_EBPF_EXTENSION_POOL_TAG);
    NET_EBPF_EXT_BAIL_ON_ALLOC_FAILURE_RESULT(
        NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, local_filter_context, "local_filter_context", result);

    memset(local_filter_context, 0, filter_context_size);

    local_filter_context->client_contexts = (net_ebpf_extension_hook_client_t**)ExAllocatePoolUninitialized(
        NonPagedPoolNx,
        client_context_count_max * sizeof(net_ebpf_extension_hook_client_t*),
        NET_EBPF_EXTENSION_POOL_TAG);
    NET_EBPF_EXT_BAIL_ON_ALLOC_FAILURE_RESULT(
        NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
        local_filter_context->client_contexts,
        "local_filter_context - client_contexts",
        result);

    memset(
        local_filter_context->client_contexts, 0, client_context_count_max * sizeof(net_ebpf_extension_hook_client_t*));
    local_filter_context->client_context_count_max = client_context_count_max;
    local_filter_context->context_deleting = FALSE;
    InitializeListHead(&local_filter_context->link);
    local_filter_context->reference_count = 1; // Initial reference.

    // Set the first client context.
    local_filter_context->client_contexts[0] = (net_ebpf_extension_hook_client_t*)client_context;
    local_filter_context->client_context_count = 1;

    // Set filter context as provider data in the hook client.
    net_ebpf_extension_hook_client_set_provider_data(
        (net_ebpf_extension_hook_client_t*)client_context, local_filter_context);

    // Set the provider context.
    local_filter_context->provider_context = provider_context;

    // Open the WFP engine handle.
    status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &local_filter_context->wfp_engine_handle);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, "FwpmEngineOpen", status);
        result = EBPF_FAILED;
        goto Exit;
    }

    *filter_context = local_filter_context;
    local_filter_context = NULL;

Exit:
    if (local_filter_context != NULL) {
        CLEAN_UP_FILTER_CONTEXT(local_filter_context);
    }

    NET_EBPF_EXT_RETURN_RESULT(result);
}

void
net_ebpf_extension_wfp_filter_context_cleanup(_Frees_ptr_ net_ebpf_extension_wfp_filter_context_t* filter_context)
{
    // Since the hook client is detaching, the eBPF program should not be invoked any further.
    // The context_deleting field in filter_context is set to false for this reason. This way any
    // lingering WFP classify callbacks will exit as it would not find any hook client associated
    // with the filter context. This is best effort & no locks are held.
    filter_context->context_deleting = TRUE;
    net_ebpf_ext_add_filter_context_to_cleanup_list(filter_context);
    DEREFERENCE_FILTER_CONTEXT(filter_context);
}

net_ebpf_extension_hook_id_t
net_ebpf_extension_get_hook_id_from_wfp_layer_id(uint16_t wfp_layer_id)
{
    net_ebpf_extension_hook_id_t hook_id = (net_ebpf_extension_hook_id_t)0;

    switch (wfp_layer_id) {
    case FWPS_LAYER_OUTBOUND_MAC_FRAME_NATIVE:
        hook_id = EBPF_HOOK_OUTBOUND_L2;
        break;
    case FWPS_LAYER_INBOUND_MAC_FRAME_NATIVE:
        hook_id = EBPF_HOOK_INBOUND_L2;
        break;
    case FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V4:
        hook_id = EBPF_HOOK_ALE_RESOURCE_ALLOC_V4;
        break;
    case FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V6:
        hook_id = EBPF_HOOK_ALE_RESOURCE_ALLOC_V6;
        break;
    case FWPS_LAYER_ALE_RESOURCE_RELEASE_V4:
        hook_id = EBPF_HOOK_ALE_RESOURCE_RELEASE_V4;
        break;
    case FWPS_LAYER_ALE_RESOURCE_RELEASE_V6:
        hook_id = EBPF_HOOK_ALE_RESOURCE_RELEASE_V6;
        break;
    case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
        hook_id = EBPF_HOOK_ALE_AUTH_CONNECT_V4;
        break;
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
        hook_id = EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V4;
        break;
    case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
        hook_id = EBPF_HOOK_ALE_AUTH_CONNECT_V6;
        break;
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
        hook_id = EBPF_HOOK_ALE_AUTH_RECV_ACCEPT_V6;
        break;
    case FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4:
        hook_id = EBPF_HOOK_ALE_FLOW_ESTABLISHED_V4;
        break;
    case FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6:
        hook_id = EBPF_HOOK_ALE_FLOW_ESTABLISHED_V6;
        break;
    case FWPS_LAYER_ALE_CONNECT_REDIRECT_V4:
        hook_id = EBPF_HOOK_ALE_CONNECT_REDIRECT_V4;
        break;
    case FWPS_LAYER_ALE_CONNECT_REDIRECT_V6:
        hook_id = EBPF_HOOK_ALE_CONNECT_REDIRECT_V6;
        break;
    default:
        ASSERT(FALSE);
        break;
    }

    return hook_id;
}

uint32_t
net_ebpf_extension_get_callout_id_for_hook(net_ebpf_extension_hook_id_t hook_id)
{
    uint32_t callout_id = 0;

    if (hook_id < EBPF_COUNT_OF(_net_ebpf_ext_wfp_callout_states)) {
        callout_id = _net_ebpf_ext_wfp_callout_states[hook_id].assigned_callout_id;
    }

    return callout_id;
}

void
net_ebpf_extension_delete_wfp_filters(
    _In_ HANDLE wfp_engine_handle,
    uint32_t filter_count,
    _Frees_ptr_ _In_count_(filter_count) net_ebpf_ext_wfp_filter_id_t* filter_ids)
{
    NET_EBPF_EXT_LOG_ENTRY();
    NTSTATUS status = STATUS_SUCCESS;

    ASSERT(wfp_engine_handle != NULL);

    for (uint32_t index = 0; index < filter_count; index++) {
        filter_ids[index].state = NET_EBPF_EXT_WFP_FILTER_DELETING;
        status = FwpmFilterDeleteById(wfp_engine_handle, filter_ids[index].id);
        filter_ids[index].error_code = status;
        if (!NT_SUCCESS(status)) {
            NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64(
                NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
                NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
                "FwpmFilterDeleteById failed to mark WFP filter for deletion.",
                status,
                filter_ids[index].id);
            filter_ids[index].state = NET_EBPF_EXT_WFP_FILTER_DELETE_FAILED;
        } else {
            NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64(
                NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
                NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
                "FwpmFilterDeleteById successfully marked WFP filter for deletion",
                index,
                filter_ids[index].id);
        }
    }
    NET_EBPF_EXT_LOG_EXIT();
}

_Must_inspect_result_ ebpf_result_t
net_ebpf_extension_add_wfp_filters(
    _In_ HANDLE wfp_engine_handle,
    uint32_t filter_count,
    _In_count_(filter_count) const net_ebpf_extension_wfp_filter_parameters_t* parameters,
    uint32_t condition_count,
    _In_opt_count_(condition_count) const FWPM_FILTER_CONDITION* conditions,
    _Inout_ net_ebpf_extension_wfp_filter_context_t* filter_context,
    _Outptr_result_buffer_maybenull_(filter_count) net_ebpf_ext_wfp_filter_id_t** filter_ids)
{
    NTSTATUS status = STATUS_SUCCESS;
    ebpf_result_t result = EBPF_SUCCESS;
    bool is_in_transaction = FALSE;
    net_ebpf_ext_wfp_filter_id_t* local_filter_ids = NULL;
    *filter_ids = NULL;

    NET_EBPF_EXT_LOG_ENTRY();

    ASSERT(wfp_engine_handle != NULL);

    if (filter_count == 0) {
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR, NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, "Filter count is 0");
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }

    local_filter_ids = (net_ebpf_ext_wfp_filter_id_t*)ExAllocatePoolUninitialized(
        NonPagedPoolNx, (sizeof(net_ebpf_ext_wfp_filter_id_t) * filter_count), NET_EBPF_EXTENSION_POOL_TAG);
    NET_EBPF_EXT_BAIL_ON_ALLOC_FAILURE_RESULT(
        NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, local_filter_ids, "local_filter_ids", result);

    memset(local_filter_ids, 0, (sizeof(net_ebpf_ext_wfp_filter_id_t) * filter_count));

    status = FwpmTransactionBegin(wfp_engine_handle, 0);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, "FwpmTransactionBegin", status);
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }
    is_in_transaction = TRUE;

    for (uint32_t index = 0; index < filter_count; index++) {
        FWPM_FILTER filter = {0};
        uint64_t local_filter_id = 0;
        const net_ebpf_extension_wfp_filter_parameters_t* filter_parameter = &parameters[index];

        filter.layerKey = *filter_parameter->layer_guid;
        filter.displayData.name = (wchar_t*)filter_parameter->name;
        filter.displayData.description = (wchar_t*)filter_parameter->description;
        filter.providerKey = (GUID*)&EBPF_WFP_PROVIDER;
        filter.action.type =
            filter_parameter->action_type ? filter_parameter->action_type : FWP_ACTION_CALLOUT_TERMINATING;
        filter.action.calloutKey = *filter_parameter->callout_guid;
        filter.filterCondition = (FWPM_FILTER_CONDITION*)conditions;
        filter.numFilterConditions = condition_count;
        if (filter_parameter->sublayer_guid != NULL) {
            filter.subLayerKey = *(filter_parameter->sublayer_guid);
        } else {
            filter.subLayerKey = EBPF_DEFAULT_SUBLAYER;
        }
        filter.weight.type = FWP_EMPTY; // auto-weight.
        REFERENCE_FILTER_CONTEXT(filter_context);
        filter.rawContext = (uint64_t)(uintptr_t)filter_context;

        status = FwpmFilterAdd(wfp_engine_handle, &filter, NULL, &local_filter_id);
        if (!NT_SUCCESS(status)) {
            NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING(
                NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
                "FwpmFilterAdd",
                status,
                "Failed to add filter",
                (char*)filter_parameter->name);
            result = EBPF_INVALID_ARGUMENT;
            goto Exit;
        } else {
            local_filter_ids[index].id = local_filter_id;
            local_filter_ids[index].name = (wchar_t*)filter_parameter->name;
            local_filter_ids[index].state = NET_EBPF_EXT_WFP_FILTER_ADDED;
            NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64(
                NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
                NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
                "Added WFP filter: ",
                index,
                local_filter_id);
        }
    }

    status = FwpmTransactionCommit(wfp_engine_handle);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, "FwpmTransactionCommit", status);
        result = EBPF_INVALID_ARGUMENT;
        goto Exit;
    }
    is_in_transaction = FALSE;

    *filter_ids = local_filter_ids;

Exit:
    if (!NT_SUCCESS(status)) {
        if (local_filter_ids != NULL) {
            ExFreePool(local_filter_ids);
        }
        if (is_in_transaction) {
            status = FwpmTransactionAbort(wfp_engine_handle);
            if (!NT_SUCCESS(status)) {
                NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(
                    NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, "FwpmTransactionAbort", status);
            }
        }
    }

    NET_EBPF_EXT_RETURN_RESULT(result);
}

static NTSTATUS
_net_ebpf_ext_register_wfp_callout(_Inout_ net_ebpf_ext_wfp_callout_state_t* callout_state, _Inout_ void* device_object)
/* ++

   This function registers callouts and filters.

-- */
{
    NTSTATUS status = STATUS_SUCCESS;

    NET_EBPF_EXT_LOG_ENTRY();

    FWPS_CALLOUT callout_register_state = {0};
    FWPM_CALLOUT callout_add_state = {0};
    FWPM_DISPLAY_DATA display_data = {0};
    BOOLEAN was_callout_registered = FALSE;

    callout_register_state.calloutKey = *callout_state->callout_guid;
    callout_register_state.classifyFn = callout_state->classify_fn;
    callout_register_state.notifyFn = callout_state->notify_fn;
    callout_register_state.flowDeleteFn = callout_state->delete_fn;
    callout_register_state.flags = 0;

    status = FwpsCalloutRegister(device_object, &callout_register_state, &callout_state->assigned_callout_id);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING(
            NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
            "FwpsCalloutRegister",
            status,
            "Failed to register callout",
            (char*)callout_state->name);
        goto Exit;
    }
    was_callout_registered = TRUE;

    display_data.name = callout_state->name;
    display_data.description = callout_state->description;

    callout_add_state.calloutKey = *callout_state->callout_guid;
    callout_add_state.displayData = display_data;
    callout_add_state.providerKey = (GUID*)&EBPF_WFP_PROVIDER;
    callout_add_state.applicableLayer = *callout_state->layer_guid;

    status = FwpmCalloutAdd(_fwp_engine_handle, &callout_add_state, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE_MESSAGE_STRING(
            NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
            "FwpmCalloutAdd",
            status,
            "Failed to add callout",
            (char*)callout_state->name);
        goto Exit;
    }

Exit:

    if (!NT_SUCCESS(status)) {
        if (was_callout_registered) {
            status = FwpsCalloutUnregisterById(callout_state->assigned_callout_id);
            if (!NT_SUCCESS(status)) {
                NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(
                    NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, "FwpsCalloutUnregisterById", status);
            } else {
                callout_state->assigned_callout_id = 0;
            }
        }
    }

    NET_EBPF_EXT_RETURN_NTSTATUS(status);
}

NTSTATUS
net_ebpf_ext_initialize_ndis_handles(_In_ const DRIVER_OBJECT* driver_object)
{
    NTSTATUS status = STATUS_SUCCESS;
    NET_BUFFER_LIST_POOL_PARAMETERS nbl_pool_parameters = {0};
    NDIS_HANDLE local_net_ebpf_ext_ndis_handle = NULL;
    NDIS_HANDLE local_net_ebpf_ext_nbl_pool_handle = NULL;

    NET_EBPF_EXT_LOG_ENTRY();

    local_net_ebpf_ext_ndis_handle =
        NdisAllocateGenericObject((DRIVER_OBJECT*)driver_object, NET_EBPF_EXTENSION_POOL_TAG, 0);
    if (local_net_ebpf_ext_ndis_handle == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(
            NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, "NdisAllocateGenericObject", status);
        goto Exit;
    }

    nbl_pool_parameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    nbl_pool_parameters.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    nbl_pool_parameters.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    nbl_pool_parameters.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
    nbl_pool_parameters.fAllocateNetBuffer = TRUE;
    nbl_pool_parameters.DataSize = 0;
    nbl_pool_parameters.PoolTag = NET_EBPF_EXTENSION_POOL_TAG;

    local_net_ebpf_ext_nbl_pool_handle =
        NdisAllocateNetBufferListPool(local_net_ebpf_ext_ndis_handle, &nbl_pool_parameters);
    if (local_net_ebpf_ext_nbl_pool_handle == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(
            NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, "NdisAllocateNetBufferListPool", status);

        NdisFreeGenericObject((PNDIS_GENERIC_OBJECT)local_net_ebpf_ext_ndis_handle);
        goto Exit;
    }

    _net_ebpf_ext_ndis_handle = local_net_ebpf_ext_ndis_handle;
    _net_ebpf_ext_nbl_pool_handle = local_net_ebpf_ext_nbl_pool_handle;

Exit:
    NET_EBPF_EXT_RETURN_NTSTATUS(status);
}

void
net_ebpf_ext_uninitialize_ndis_handles()
{
    if (_net_ebpf_ext_nbl_pool_handle != NULL) {
        NdisFreeNetBufferListPool(_net_ebpf_ext_nbl_pool_handle);
    }

    if (_net_ebpf_ext_ndis_handle != NULL) {
        NdisFreeGenericObject((NDIS_GENERIC_OBJECT*)_net_ebpf_ext_ndis_handle);
    }
}

NTSTATUS
net_ebpf_extension_initialize_wfp_components(_Inout_ void* device_object)
/* ++

   This function initializes various WFP related components.

-- */
{
    UNREFERENCED_PARAMETER(device_object);
    NTSTATUS status = STATUS_SUCCESS;
    FWPM_PROVIDER ebpf_wfp_provider = {0};
    FWPM_SUBLAYER ebpf_hook_sub_layer;
    BOOLEAN is_engine_opened = FALSE;
    BOOLEAN is_in_transaction = FALSE;
    size_t index;

    NET_EBPF_EXT_LOG_ENTRY();

    if (_fwp_engine_handle != NULL) {
        // already registered
        goto Exit;
    }

    InitializeListHead(&_net_ebpf_ext_wfp_cleanup_state.provider_context_cleanup_list);
    InitializeListHead(&_net_ebpf_ext_wfp_cleanup_state.filter_cleanup_list);
    KeInitializeEvent(&_net_ebpf_ext_wfp_cleanup_state.wfp_filter_cleanup_event, NotificationEvent, FALSE);

    status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &_fwp_engine_handle);
    NET_EBPF_EXT_BAIL_ON_API_FAILURE_STATUS(NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, "FwpmEngineOpen", status);
    is_engine_opened = TRUE;

    status = FwpmTransactionBegin(_fwp_engine_handle, 0);
    NET_EBPF_EXT_BAIL_ON_API_FAILURE_STATUS(NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, "FwpmTransactionBegin", status);
    is_in_transaction = TRUE;

    // Create the WFP provider.
    ebpf_wfp_provider.displayData.name = L"eBPF for Windows contributors";
    ebpf_wfp_provider.displayData.description = L"Windows Networking eBPF Extension";
    ebpf_wfp_provider.providerKey = EBPF_WFP_PROVIDER;
    status = FwpmProviderAdd(_fwp_engine_handle, &ebpf_wfp_provider, NULL);
    NET_EBPF_EXT_BAIL_ON_API_FAILURE_STATUS(NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, "FwpmProviderAdd", status);

    // Add all the sub layers.
    for (index = 0; index < EBPF_COUNT_OF(_net_ebpf_ext_sublayers); index++) {
        RtlZeroMemory(&ebpf_hook_sub_layer, sizeof(FWPM_SUBLAYER));

        ebpf_hook_sub_layer.subLayerKey = *(_net_ebpf_ext_sublayers[index].sublayer_guid);
        ebpf_hook_sub_layer.displayData.name = (wchar_t*)_net_ebpf_ext_sublayers[index].name;
        ebpf_hook_sub_layer.displayData.description = (wchar_t*)_net_ebpf_ext_sublayers[index].description;
        ebpf_hook_sub_layer.providerKey = (GUID*)&EBPF_WFP_PROVIDER;
        ebpf_hook_sub_layer.flags = _net_ebpf_ext_sublayers[index].flags;
        ebpf_hook_sub_layer.weight = _net_ebpf_ext_sublayers[index].weight;

        status = FwpmSubLayerAdd(_fwp_engine_handle, &ebpf_hook_sub_layer, NULL);
        NET_EBPF_EXT_BAIL_ON_API_FAILURE_STATUS(NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, "FwpmSubLayerAdd", status);
    }

    for (index = 0; index < EBPF_COUNT_OF(_net_ebpf_ext_wfp_callout_states); index++) {
        status = _net_ebpf_ext_register_wfp_callout(&_net_ebpf_ext_wfp_callout_states[index], device_object);
        if (!NT_SUCCESS(status)) {
            NET_EBPF_EXT_LOG_MESSAGE_STRING(
                NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
                NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
                "_net_ebpf_ext_register_wfp_callout() failed to register callout",
                (char*)_net_ebpf_ext_wfp_callout_states[index].name);
            goto Exit;
        }
    }

    status = FwpmTransactionCommit(_fwp_engine_handle);
    NET_EBPF_EXT_BAIL_ON_API_FAILURE_STATUS(NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, "FwpmTransactionCommit", status);
    is_in_transaction = FALSE;

    // Create L2 injection handle.
    status = FwpsInjectionHandleCreate(AF_LINK, FWPS_INJECTION_TYPE_L2, &_net_ebpf_ext_l2_injection_handle);
    NET_EBPF_EXT_BAIL_ON_API_FAILURE_STATUS(
        NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, "FwpsInjectionHandleCreate", status);

Exit:

    if (!NT_SUCCESS(status)) {
        if (is_in_transaction) {
            NTSTATUS abort_status = FwpmTransactionAbort(_fwp_engine_handle);
            if (!NT_SUCCESS(abort_status)) {
                NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(
                    NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, "FwpmTransactionAbort", abort_status);
            }
        }

        if (is_engine_opened) {
            net_ebpf_extension_uninitialize_wfp_components();
        }
    }

    NET_EBPF_EXT_RETURN_NTSTATUS(status);
}

void
net_ebpf_extension_uninitialize_wfp_components(void)
{
    size_t index;
    NTSTATUS status;
    const int max_retries = 10;
    LARGE_INTEGER timeout = {0};
    timeout.QuadPart = -SECONDSTO100NS(10);

    NET_EBPF_EXT_LOG_ENTRY();

    if (_fwp_engine_handle != NULL) {
        // WFP operations may fail if connections are in the middle of being classified and our WFP filters or callouts
        // are in use. Prior to this function execution, it is expected that the WFP filter objects were removed,
        // reducing the risk of this failure to occur. However, the following cleanup functions have retry logic built
        // in to help ensure that the WFP objects are cleaned up properly.

        // Clean up the callouts.
        for (index = 0; index < EBPF_COUNT_OF(_net_ebpf_ext_wfp_callout_states); index++) {

            for (int i = 1; i <= max_retries; i++) {
                status = FwpsCalloutUnregisterById(_net_ebpf_ext_wfp_callout_states[index].assigned_callout_id);
                if (NT_SUCCESS(status) || WFP_ERROR(status, CALLOUT_NOT_FOUND)) {
                    break;
                }

                if (i == max_retries) {
                    NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(
                        NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, "FwpsCalloutUnregisterById", status);
                }
            }

            for (int i = 1; i <= max_retries; i++) {
                status =
                    FwpmCalloutDeleteByKey(_fwp_engine_handle, _net_ebpf_ext_wfp_callout_states[index].callout_guid);
                if (NT_SUCCESS(status) || WFP_ERROR(status, CALLOUT_NOT_FOUND)) {
                    break;
                }

                if (i == max_retries) {
                    NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(
                        NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, "FwpmCalloutDeleteByKey", status);
                }
            }
        }

        // Clean up the sub layers.
        for (index = 0; index < EBPF_COUNT_OF(_net_ebpf_ext_sublayers); index++) {
            for (int i = 1; i <= max_retries; i++) {
                status = FwpmSubLayerDeleteByKey(_fwp_engine_handle, _net_ebpf_ext_sublayers[index].sublayer_guid);
                if (NT_SUCCESS(status) || WFP_ERROR(status, SUBLAYER_NOT_FOUND)) {
                    break;
                }

                if (i == max_retries) {
                    NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(
                        NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, "FwpmSubLayerDeleteByKey", status);
                }
            }
        }

        // Clean up the providers.
        for (int i = 1; i <= max_retries; i++) {
            status = FwpmProviderDeleteByKey(_fwp_engine_handle, &EBPF_WFP_PROVIDER);
            if (NT_SUCCESS(status) || WFP_ERROR(status, PROVIDER_NOT_FOUND)) {
                break;
            }

            if (i == max_retries) {
                NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(
                    NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, "FwpmProviderDeleteByKey", status);
            }
        }

        // Close the engine handle.
        status = FwpmEngineClose(_fwp_engine_handle);
        if (!NT_SUCCESS(status)) {
            NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, "FwpmEngineClose", status);
        }
        _fwp_engine_handle = NULL;
    }

    // FwpsInjectionHandleCreate can fail. So, check for NULL.
    if (_net_ebpf_ext_l2_injection_handle != NULL) {
        status = FwpsInjectionHandleDestroy(_net_ebpf_ext_l2_injection_handle);
        if (!NT_SUCCESS(status)) {
            NET_EBPF_EXT_LOG_NTSTATUS_API_FAILURE(
                NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION, "FwpsInjectionHandleDestroy", status);
        }
    }

    // If there are cleanup filters, sleep to give WFP time to issue callbacks. Once this timeout completes,
    // we assume that any remaining notifications will not be issued, and proceed with cleanup.
    KIRQL old_irql = ExAcquireSpinLockExclusive(&_net_ebpf_ext_wfp_cleanup_state.lock);
    if (!IsListEmpty(&_net_ebpf_ext_wfp_cleanup_state.filter_cleanup_list)) {
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
            NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
            "Leaked WFP Filters found. Processing cleanup.");
        _net_ebpf_ext_wfp_cleanup_state.signal_empty_filter_list = TRUE;

        // Allow some time for WFP to signal deletion for the filters. KeWaitForSingleObject also requires dropping the
        // IRQL level and therefore the lock.
        ExReleaseSpinLockExclusive(&_net_ebpf_ext_wfp_cleanup_state.lock, old_irql);
        status = KeWaitForSingleObject(
            &_net_ebpf_ext_wfp_cleanup_state.wfp_filter_cleanup_event, Executive, KernelMode, FALSE, &timeout);
        old_irql = ExAcquireSpinLockExclusive(&_net_ebpf_ext_wfp_cleanup_state.lock);

#pragma warning(push)
#pragma warning(disable : 6001) // Using uninitialized memory 'filter_context' and 'filter_id'.
        // Proceed with cleanup - assume that any remaining notifications will never be issued by WFP,
        // and continue with cleaning up our internal state.
        while (!IsListEmpty(&_net_ebpf_ext_wfp_cleanup_state.filter_cleanup_list)) {
            uint32_t leaked_filter_count = 0;
            PLIST_ENTRY entry = RemoveHeadList(&_net_ebpf_ext_wfp_cleanup_state.filter_cleanup_list);
            net_ebpf_extension_wfp_filter_context_t* filter_context =
                CONTAINING_RECORD(entry, net_ebpf_extension_wfp_filter_context_t, link);
            InitializeListHead(&filter_context->link);

            // Release lock as we process the entry. DEREFERENCE_FILTER_CONTEXT also acquires the lock.
            ExReleaseSpinLockExclusive(&_net_ebpf_ext_wfp_cleanup_state.lock, old_irql);

            // Anything left in the NET_EBPF_EXT_WFP_FILTER_DELETING is considered leaked. Remove the references
            // to allow for cleanup.
            for (index = 0; index < filter_context->filter_ids_count; index++) {
                net_ebpf_ext_wfp_filter_id_t* filter_id = &filter_context->filter_ids[index];
                if (filter_id->state == NET_EBPF_EXT_WFP_FILTER_DELETING) {
                    leaked_filter_count++;
                    NET_EBPF_EXT_LOG_MESSAGE_UINT64(
                        NET_EBPF_EXT_TRACELOG_LEVEL_WARNING,
                        NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
                        "Releasing reference for leaked WFP filter.",
                        filter_id->id);
                }
            }

            // Remove remaining references.
            ASSERT(filter_context->reference_count == (long)leaked_filter_count);
            for (index = 0; index < leaked_filter_count; index++) {
                DEREFERENCE_FILTER_CONTEXT(filter_context);
            }

            old_irql = ExAcquireSpinLockExclusive(&_net_ebpf_ext_wfp_cleanup_state.lock);
        }
#pragma warning(pop)
    }

    // Iterate through the provider list and handle cleanup.
    while (!IsListEmpty(&_net_ebpf_ext_wfp_cleanup_state.provider_context_cleanup_list)) {
        PLIST_ENTRY entry = RemoveHeadList(&_net_ebpf_ext_wfp_cleanup_state.provider_context_cleanup_list);
        net_ebpf_extension_hook_provider_t* provider_context =
            CONTAINING_RECORD(entry, net_ebpf_extension_hook_provider_t, cleanup_list_entry);

        // Release the lock as waiting for rundown can take time.
        ExReleaseSpinLockExclusive(&_net_ebpf_ext_wfp_cleanup_state.lock, old_irql);
        _ebpf_ext_wait_for_rundown(&provider_context->rundown);
        ExFreePool(provider_context);

        // Re-acquire the lock.
        old_irql = ExAcquireSpinLockExclusive(&_net_ebpf_ext_wfp_cleanup_state.lock);
    }

    ExReleaseSpinLockExclusive(&_net_ebpf_ext_wfp_cleanup_state.lock, old_irql);

    NET_EBPF_EXT_LOG_EXIT();
}

NTSTATUS
net_ebpf_ext_filter_change_notify(
    FWPS_CALLOUT_NOTIFY_TYPE callout_notification_type, _In_ const GUID* filter_key, _Inout_ FWPS_FILTER* filter)
{
    NET_EBPF_EXT_LOG_ENTRY();

    UNREFERENCED_PARAMETER(filter_key);

    if (callout_notification_type == FWPS_CALLOUT_NOTIFY_DELETE_FILTER) {
        net_ebpf_extension_wfp_filter_context_t* filter_context =
            (net_ebpf_extension_wfp_filter_context_t*)(uintptr_t)filter->context;

        for (uint32_t index = 0; index < filter_context->filter_ids_count; index++) {
            net_ebpf_ext_wfp_filter_id_t* cur_filter_id = &filter_context->filter_ids[index];
            if (cur_filter_id->id == filter->filterId) {
                cur_filter_id->state = NET_EBPF_EXT_WFP_FILTER_DELETED;
                NET_EBPF_EXT_LOG_MESSAGE_UINT64_UINT64(
                    NET_EBPF_EXT_TRACELOG_LEVEL_VERBOSE,
                    NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
                    "Received WFP filter delete callback.",
                    index,
                    cur_filter_id->id);

                break;
            }
        }
        DEREFERENCE_FILTER_CONTEXT((filter_context));
    }

    NET_EBPF_EXT_RETURN_NTSTATUS(STATUS_SUCCESS);
}

static void
_net_ebpf_ext_flow_delete(uint16_t layer_id, uint32_t callout_id, uint64_t flow_context)
/* ++

   This is the flowDeleteFn function of the L2 callout.

-- */
{
    UNREFERENCED_PARAMETER(layer_id);
    UNREFERENCED_PARAMETER(callout_id);
    UNREFERENCED_PARAMETER(flow_context);
    return;
}

NTSTATUS
net_ebpf_ext_register_providers()
{
    NTSTATUS status = STATUS_SUCCESS;

    NET_EBPF_EXT_LOG_ENTRY();

    status = net_ebpf_ext_xdp_register_providers();
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
            "net_ebpf_ext_xdp_register_providers failed.",
            status);
        goto Exit;
    }
    _net_ebpf_xdp_providers_registered = true;

    status = net_ebpf_ext_bind_register_providers();
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
            "net_ebpf_ext_bind_register_providers failed.",
            status);
        goto Exit;
    }
    _net_ebpf_bind_providers_registered = true;

    status = net_ebpf_ext_sock_addr_register_providers();
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
            "net_ebpf_ext_bind_register_providers failed.",
            status);
        goto Exit;
    }
    _net_ebpf_sock_addr_providers_registered = true;

    status = net_ebpf_ext_sock_ops_register_providers();
    if (!NT_SUCCESS(status)) {
        NET_EBPF_EXT_LOG_MESSAGE_NTSTATUS(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
            "net_ebpf_ext_sock_ops_register_providers failed.",
            status);
        goto Exit;
    }
    _net_ebpf_sock_ops_providers_registered = true;

Exit:
    if (!NT_SUCCESS(status)) {
        net_ebpf_ext_unregister_providers();
    }
    NET_EBPF_EXT_RETURN_NTSTATUS(status);
}

void
net_ebpf_ext_unregister_providers()
{
    NET_EBPF_EXT_LOG_ENTRY();

    if (_net_ebpf_xdp_providers_registered) {
        net_ebpf_ext_xdp_unregister_providers();
        _net_ebpf_xdp_providers_registered = false;
    }
    if (_net_ebpf_bind_providers_registered) {
        net_ebpf_ext_bind_unregister_providers();
        _net_ebpf_bind_providers_registered = false;
    }
    if (_net_ebpf_sock_addr_providers_registered) {
        net_ebpf_ext_sock_addr_unregister_providers();
        _net_ebpf_sock_addr_providers_registered = false;
    }
    if (_net_ebpf_sock_ops_providers_registered) {
        net_ebpf_ext_sock_ops_unregister_providers();
        _net_ebpf_sock_ops_providers_registered = false;
    }

    NET_EBPF_EXT_LOG_EXIT();
}

ebpf_result_t
net_ebpf_ext_add_client_context(
    _Inout_ net_ebpf_extension_wfp_filter_context_t* filter_context,
    _In_ const struct _net_ebpf_extension_hook_client* hook_client)
{
    ebpf_result_t result = EBPF_SUCCESS;
    KIRQL old_irql;

    NET_EBPF_EXT_LOG_ENTRY();

    old_irql = ExAcquireSpinLockExclusive(&filter_context->lock);

    // Check if we have reached max capacity.
    if (filter_context->client_context_count == filter_context->client_context_count_max) {
        NET_EBPF_EXT_LOG_MESSAGE(
            NET_EBPF_EXT_TRACELOG_LEVEL_ERROR,
            NET_EBPF_EXT_TRACELOG_KEYWORD_EXTENSION,
            "net_ebpf_ext_add_client_context: Exceeded max client count");
        result = EBPF_NO_MEMORY;
        goto Exit;
    }

    // Append the client context to the end.
    filter_context->client_contexts[filter_context->client_context_count] =
        (struct _net_ebpf_extension_hook_client*)hook_client;
    filter_context->client_context_count++;

    // Add filter_context as provider data for the client.
    net_ebpf_extension_hook_client_set_provider_data(
        (struct _net_ebpf_extension_hook_client*)hook_client, (void*)filter_context);

Exit:
    ExReleaseSpinLockExclusive(&filter_context->lock, old_irql);
    NET_EBPF_EXT_RETURN_RESULT(result);
}

void
net_ebpf_ext_remove_client_context(
    _Inout_ net_ebpf_extension_wfp_filter_context_t* filter_context,
    _In_ const struct _net_ebpf_extension_hook_client* hook_client)
{
    KIRQL old_irql;
    uint32_t index;
    bool found = FALSE;

    old_irql = ExAcquireSpinLockExclusive(&filter_context->lock);

    for (index = 0; index < filter_context->client_context_count; index++) {
        if (filter_context->client_contexts[index] == hook_client) {
            filter_context->client_contexts[index] = NULL;
            filter_context->client_context_count--;
            found = TRUE;
            break;
        }
    }
    ASSERT(found == TRUE);
    if (index != filter_context->client_context_count) {
        memcpy(
            &filter_context->client_contexts[index],
            &filter_context->client_contexts[index + 1],
            (filter_context->client_context_count - index) * sizeof(net_ebpf_extension_hook_client_t*));

        filter_context->client_contexts[filter_context->client_context_count] = NULL;
    }

    ExReleaseSpinLockExclusive(&filter_context->lock, old_irql);
}

void
net_ebpf_ext_add_provider_context_to_cleanup_list(_Inout_ net_ebpf_extension_hook_provider_t* provider_context)
{
    KIRQL old_irql = ExAcquireSpinLockExclusive(&_net_ebpf_ext_wfp_cleanup_state.lock);
    InsertTailList(
        &_net_ebpf_ext_wfp_cleanup_state.provider_context_cleanup_list, &provider_context->cleanup_list_entry);
    ExReleaseSpinLockExclusive(&_net_ebpf_ext_wfp_cleanup_state.lock, old_irql);
}

void
net_ebpf_ext_add_filter_context_to_cleanup_list(_Inout_ net_ebpf_extension_wfp_filter_context_t* filter_context)
{
    KIRQL old_irql = ExAcquireSpinLockExclusive(&_net_ebpf_ext_wfp_cleanup_state.lock);
    InsertTailList(&_net_ebpf_ext_wfp_cleanup_state.filter_cleanup_list, &filter_context->link);
    ExReleaseSpinLockExclusive(&_net_ebpf_ext_wfp_cleanup_state.lock, old_irql);
}

void
net_ebpf_ext_remove_filter_context_from_cleanup_list(_Inout_ net_ebpf_extension_wfp_filter_context_t* filter_context)
{
    if (!IsListEmpty(&filter_context->link)) {
        KIRQL old_irql = ExAcquireSpinLockExclusive(&_net_ebpf_ext_wfp_cleanup_state.lock);
        RemoveEntryList(&filter_context->link);
        InitializeListHead(&filter_context->link);
        if (IsListEmpty(&_net_ebpf_ext_wfp_cleanup_state.filter_cleanup_list) &&
            _net_ebpf_ext_wfp_cleanup_state.signal_empty_filter_list) {
            KeSetEvent(&_net_ebpf_ext_wfp_cleanup_state.wfp_filter_cleanup_event, 0, FALSE);
        }
        ExReleaseSpinLockExclusive(&_net_ebpf_ext_wfp_cleanup_state.lock, old_irql);
    }
}