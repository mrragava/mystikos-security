// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/globals.h>
#include <stdint.h>
#include <stdlib.h>
#include "fuzzsupport_t.h"
#include "pthread.h"
#include "myst_tcalls.h"
#include "syscall.h"
#include "syscallfuzzer.h"

__attribute__((visibility("default")))
uint64_t __sanitizer_get_host_tpc()
{
    uint64_t tpc = 0;
    oe_get_tpc_ocall(&tpc);
    return tpc;
}

__attribute__((visibility("default")))
void __asan_send_command_to_symbolizer(uint64_t module_offset, char** symbol)
{
    oe_get_symbol_ocall(oe_get_enclave(), module_offset, symbol);
}

__attribute__((visibility("default")))
void __sanitizer_die()
{
    oe_die_ocall();
}

void *__dlsym(void *restrict handle, const char *restrict name, void *restrict sym_addr)
{
    void* ret = NULL;
    oe_result_t result = OE_UNEXPECTED;
    OE_UNUSED(handle);
    OE_UNUSED(sym_addr);

    uint64_t offset = 0ULL;
    if (oe_get_symbol_offset_ocall(&result, oe_get_enclave(), name, &offset) != OE_OK)
        goto done;

    if (result != OE_OK)
        goto done;

    const uint8_t* baseaddr = (const uint8_t*)__oe_get_enclave_base();
    uint64_t* dest = (uint64_t*)(baseaddr + offset);

    ret = (void*)dest;

    size_t enc_size = __oe_get_heap_size();
    enc_size = enc_size;

done:
    return ret;
}

// void *kernel_dlsym(void *restrict handle, const char *restrict name, void *restrict sym_addr)
// {
//     void* ret = NULL;
//     oe_result_t result = OE_UNEXPECTED;
//     OE_UNUSED(handle);
//     OE_UNUSED(sym_addr);

//     uint64_t offset = 0ULL;
//     if (oe_get_symbol_offset_ocall(&result, NULL, name, &offset) != OE_OK)
//         goto done;

//     if (result != OE_OK)
//         goto done;

//     const uint8_t* baseaddr = (const uint8_t*)__oe_get_enclave_base();
//     uint64_t* dest = (uint64_t*)(baseaddr + offset);

//     ret = (void*)dest;

// done:
//     return ret;
// }

long fuzzer_tcalls(long n, long params[6])
{
    long ret = -1;
    switch (n)
    {
        case MYST_TCALL_GET_TPC:
            ret = __sanitizer_get_host_tpc();
            break;
        case MYST_TCALL_SYMBOLIZER:
            // __asan_send_command_to_symbolizer((uint64_t)params[0], (char**)params[1]);
            oe_get_symbol_ocall(NULL, (uint64_t)params[0], (char**)params[1]);
            ret = 0;
            break;
        case MYST_TCALL_DLSYM:
            ret = (long)__dlsym((void *)params[0], (const char *)params[1], (void *)params[2]);
            break;
        case MYST_TCALL_DIE:
            __sanitizer_die();
            ret = 0;
            break;
        case MYST_TCALL_BACKTRACE:
            ret = (long)backtrace((void**)params[0], (int)params[1]);
            break;
        case MYST_TCALL_BACKTRACE_SYMBOLS:
            ret = (long)backtrace_symbols((void* const*) params[0], (int)params[1]);
            break;
        case MYST_TCALL_UNWIND_RAISEEXCEPTION:
            ret = (long)_Unwind_RaiseException((struct _Unwind_Exception *)params[0]);
            break;
        case MYST_TCALL_UNWIND_BACKTRACE:
            ret = (long)_Unwind_Backtrace(params[0], (void *)params[1]);
            break;
        case MYST_TCALL_UNWIND_GETIP:
            ret = (long)_Unwind_GetIP((struct _Unwind_Context *)params[0]);
            break;
        case MYST_TCALL_GETRLIMIT:
            ret = oe_SYS_getrlimit_impl(params[0], params[1]);
            break;
        case MYST_TCALL_PTHREAD_KEY_CREATE:
            ret = pthread_key_create(params[0], params[1]);
            break;
        case MYST_TCALL_PTHREAD_KEY_DELETE:
            ret = pthread_key_delete(params[0]);
            break;
        case MYST_TCALL_PTHREAD_SET_SPECIFIC:
            ret = pthread_setspecific((pthread_key_t)params[0], (void*)params[1]);
            break;
        case MYST_TCALL_PTHREAD_GET_SPECIFIC:
            ret = pthread_getspecific((pthread_key_t)params[0]);
            break;
        case MYST_TCALL_GET_SYSCALL_FUZZER_PAYLOAD:
            {
                uint64_t syscall_payload_ptr = 0;
                oe_get_syscall_fuzzer_payload_ocall(&syscall_payload_ptr);
                *((long*)params[0]) = (long*)syscall_payload_ptr;
                ret = (syscall_payload_ptr == 0);
                break;
            }
        default:
        {
            printf("error: handle_fuzzer_tcalls=%ld\n", n);
        }
    }
    return ret;
}
