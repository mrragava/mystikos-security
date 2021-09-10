// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include "myst_tcalls.h"
#include "kernel_symbol.h"
#include <sys/syscall.h>
#include <sys/types.h> 

#define _GNU_SOURCE 1
#include "unwind.h"

extern "C" {

long myst_tcall(long n, long params[6]);
long myst_syscall(long n, long params[6]);
long myst_syscall_isatty(int fd);
size_t myst_backtrace(void** buffer, size_t size);

__attribute__((visibility("default")))
uint64_t __sanitizer_get_host_tpc()
{
    long params[6]={0};
    return (uint64_t)myst_tcall(MYST_TCALL_GET_TPC, params);
}

__attribute__((visibility("default")))
void __asan_send_command_to_symbolizer(uint64_t module_offset, char** symbol)
{
    long params[6]={0};
    params[0] = (long)module_offset;
    params[1] = (long)symbol;
    (void)myst_tcall(MYST_TCALL_SYMBOLIZER, params);
}

void *__dlsym(void* handle, const char* name, void* sym_addr)
{
    return kernel_dlsym(handle, name, sym_addr);
}

__attribute__((visibility("default")))
void __sanitizer_die()
{
    long params[6]={0};
    (void)myst_tcall(MYST_TCALL_DIE, params);
}

__attribute__((visibility("default"))) 
void InitializeSyscallHooks()
{
}

int backtrace(void** buffer, int size)
{
    long params[6]={0};
    params[0] = (long)buffer;
    params[1] = (long)size;
    return (int)myst_tcall(MYST_TCALL_BACKTRACE, params);
    // return myst_backtrace(buffer, size);
}

char** backtrace_symbols(void* const* buffer, int size)
{
    long params[6]={0};
    params[0] = (long)buffer;
    params[1] = (long)size;
    return (char**)myst_tcall(MYST_TCALL_BACKTRACE_SYMBOLS, params);
}

// _Unwind_Reason_Code _Unwind_RaiseException(struct _Unwind_Exception *exception_object)
// {
//     long params[6]={0};
//     params[0] = (long)exception_object;
//     return (_Unwind_Reason_Code)myst_tcall(MYST_TCALL_UNWIND_RAISEEXCEPTION, params);
// }

// _Unwind_Reason_Code _Unwind_Backtrace(_Unwind_Trace_Fn trace, void *trace_parameter)
// {
//     long params[6]={0};
//     params[0] = (long)trace;
//     params[1] = (long)trace_parameter;
//     return (_Unwind_Reason_Code)myst_tcall(MYST_TCALL_UNWIND_BACKTRACE, params);
// }

// unsigned long _Unwind_GetIP(struct _Unwind_Context *context)
// {
//     long params[6]={0};
//     params[0] = (long)context;
//     return (unsigned long)myst_tcall(MYST_TCALL_UNWIND_GETIP, params);
// }

int getrlimit(int resource, struct rlimit *rlim)
{
    long params[6]={0};
    params[0] = (long)resource;
    params[1] = (long)rlim;
    return (int)myst_tcall(MYST_TCALL_GETRLIMIT, params);
}

int dl_iterate_phdr(
    int (*callback)(struct dl_phdr_info* info, size_t size, void* data),
    void* data)
{
    return _dl_iterate_phdr(callback, data);
}

int isatty(int fd)
{
    return myst_syscall_isatty(fd);
}

bool oe_is_within_enclave(const void* ptr, size_t sz)
{
    return true;
}

void oe_allocator_free(void* ptr)
{
    free(ptr);
}

int oe_allocator_posix_memalign(void** memptr, size_t alignment, size_t size)
{
    return posix_memalign(memptr, alignment, size);
}

long labs(long a)
{
	return a>0 ? a : -a;
}

// long myst_tcall_set_tsd(uint64_t value)
// long myst_tcall_get_tsd(uint64_t* value)

// int pthread_setspecific(pthread_key_t k, const void *x)
// {
//     long params[6]={0};
//     params[0] = (long)k;
//     return (int) myst_tcall(MYST_TCALL_SET_TSD, params);

//     return self->tsd[k];
// }

// void *pthread_getspecific(pthread_key_t k)
// {
//     long params[6]={0};
//     params[0] = (long)k;
//     return (void *)myst_tcall(MYST_TCALL_GET_TSD, params);
// }

// void *tss_get(pthread_key_t k)
// {
//     return pthread_getspecific(k);
// }

int pthread_key_create(pthread_key_t *k, void (*dtor)(void *))
{
    long params[6]={0};
    params[0] = (long)k;
    params[1] = (long)dtor;
    return (int)myst_tcall(MYST_TCALL_PTHREAD_KEY_CREATE, params);
}

int pthread_key_delete(pthread_key_t k)
{
    long params[6]={0};
    params[0] = (long)k;
    return (int)myst_tcall(MYST_TCALL_PTHREAD_KEY_DELETE, params);
}

int pthread_setspecific(pthread_key_t k, const void *x)
{
    long params[6]={0};
    params[0] = (long)k;
    params[1] = (long)x;
    return (int)myst_tcall(MYST_TCALL_PTHREAD_SET_SPECIFIC, params);
}

void *pthread_getspecific(pthread_key_t k)
{
    long params[6]={0};
    params[0] = (long)k;
    return (void *)myst_tcall(MYST_TCALL_PTHREAD_GET_SPECIFIC, params);
}

void *tss_get(pthread_key_t k)
{
    return pthread_getspecific(k);
}

int pthread_mutex_lock(pthread_mutex_t *)
{
    return 0;
}

int pthread_mutex_unlock(pthread_mutex_t *)
{
    return 0;
}

int pthread_cond_wait(pthread_cond_t* cond, pthread_mutex_t* mutex)
{
    return 0;
}

int pthread_cond_signal(pthread_cond_t* cond)
{
    return 0;
}

void* oe_get_thread_data()
{
    return NULL;
}

int dladdr(const void* addr, void* info)
{
    return 0;
}

int isdigit(int c)
{
    return 0;
}

#include "string/wmemset.c"
#include "string/wmemmove.c"
#include "string/wmemcmp.c"

long wcstol(const wchar_t *s, wchar_t **p, int base)
{
    return 0;
}

unsigned long wcstoul(const wchar_t *s, wchar_t **p, int base)
{
	return 0;
}


long long wcstoll(const wchar_t *s, wchar_t **p, int base)
{
	return 0;
}

unsigned long long wcstoull(const wchar_t *s, wchar_t **p, int base)
{
	return 0;
}

float strtof(const char *s, char **p)
{
	return 0;
}

double strtod(const char *s, char **p)
{
	return 0;
}

long double strtold(const char *s, char **p)
{
	return 0;
}

float wcstof(const wchar_t *s, wchar_t **p)
{
	return 0;
}

double wcstod(const wchar_t *s, wchar_t **p)
{
	return 0;
}

long double wcstold(const wchar_t *s, wchar_t **p)
{
	return 0;
}

int swprintf(wchar_t *s, size_t n, const wchar_t *fmt, ...)
{
	return 0;
}

void* stderr;

bool fuzzer_initialized = false;
extern long __syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6);
long syscall(long n, ...)
{
	va_list ap;
	va_start(ap, n);
    long params[6] = { 0, 0, 0, 0, 0, 0 };
	params[0] = va_arg(ap, long);
	params[1] = va_arg(ap, long);
	params[2] = va_arg(ap, long);
	params[3] = va_arg(ap, long);
	params[4] = va_arg(ap, long);
	params[5] = va_arg(ap, long);
	va_end(ap);

    switch (n)
    {
        case SYS_readlink:
        {
            const char* pathname = (const char*)params[0];
            char* buf = (char*)params[1];
            size_t bufsiz = (size_t)params[2];

            char kernel_mod[] = "libmystkernel.so";
            if (strcmp(pathname, "/proc/self/exe") == 0)
            {
                strcpy(buf, kernel_mod);
                return strlen(kernel_mod) + 1;
            }            
        }
        // /proc/101/fd/3
        break;
    }
    return myst_syscall(n, params);
}

}
