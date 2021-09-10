// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include <bits/stdint-uintn.h>
#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include <stdint.h>
#include <stdlib.h>
#include "openenclave/host/sgx/enclave.h"
#include "fuzzsupport_args.h"
#include "fuzzsupport_u.h"
#include "syscallfuzzer.h"

#include <dlfcn.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <map>
#include <vector>

uint64_t gtpc;
syscall_fuzzer_payload* syscall_payload;

static elf64_t enclave_elf = ELF64_INIT;
static elf64_t kernel_elf = ELF64_INIT;
static bool enclave_elf_loaded = false;
static bool kernel_elf_loaded = false;

extern "C" void InitializeEnclaveFuzzer()
{
    typedef uint64_t (*fn__sanitizer_get_tpc)();
    fn__sanitizer_get_tpc fn =
        (fn__sanitizer_get_tpc)dlsym(RTLD_DEFAULT, "__sanitizer_get_tpc");
    if (fn)
        gtpc = (*fn)();
}

extern "C" void DestroyEnclaveFuzzer()
{
    if (enclave_elf_loaded)
    {
        elf64_unload(&enclave_elf);
        enclave_elf = ELF64_INIT;
        enclave_elf_loaded = false;
    }

    if (kernel_elf_loaded)
    {
        elf64_unload(&kernel_elf);
        kernel_elf = ELF64_INIT;
        kernel_elf_loaded = false;
    }
}

uint64_t oe_get_tpc_ocall()
{
    return gtpc;
}

extern "C" void set_syscall_fuzzer_payload(syscall_fuzzer_payload* payload)
{
    syscall_payload = payload;
}

uint64_t oe_get_syscall_fuzzer_payload_ocall()
{
    return reinterpret_cast<uint64_t>(syscall_payload);
}

void oe_get_enclave_module_path_ocall(oe_enclave_t* oe_enclave, char* path)
{
    if (!oe_enclave || !oe_enclave->path)
        abort();

    strcpy(path, oe_enclave->path);
}

#define PATH_MAX 255
inline bool get_proc_path(std::string &path)
{
    std::vector<char> proc_path(PATH_MAX);
    if (readlink("/proc/self/exe", proc_path.data(), PATH_MAX - 1) == -1)
        return false;
    std::string proc_dir(proc_path.begin(), proc_path.end());
    path = proc_dir.substr(0, proc_dir.rfind("/"));
    return true;
}

static const int _format_lib(char* path, size_t size, const char* suffix)
{
    int ret = 0;
    char buf[PATH_MAX];
    char* dir1;
    char* dir2;
    int n;
    std::string kernel_path;

    if (!path || !size || !suffix)
    {
        ret = -1;
        goto done;
    }

    get_proc_path(kernel_path);
    kernel_path = kernel_path.substr(0, kernel_path.rfind("/"));

    if ((n = snprintf(path, size, "%s/%s", kernel_path.c_str(), suffix)) >= size)
    {
        ret = -1;
        goto done;
    }

done:
    return ret;
}

const int format_libmystkernel(char* path, size_t size)
{
    return _format_lib(path, size, "lib/libmystkernel.so");
}

void oe_get_symbol_ocall(
    oe_enclave_t* oe_enclave,
    uint64_t module_offset,
    char** symbol)
{
    bool enclave = false;
    char* path = NULL;
    char kernel_path[PATH_MAX];
    if (oe_enclave)
    {
        enclave = true;
        path = oe_enclave->path;
    }
    else
    {
        if (format_libmystkernel(kernel_path, sizeof(kernel_path)) != 0)
        {
            abort();
        }
        path = kernel_path;
    }

    typedef void (*fn__sanitizer_get_symbol)(char*, unsigned long long, char**);
    fn__sanitizer_get_symbol fn =
        (fn__sanitizer_get_symbol)dlsym(RTLD_DEFAULT, "__sanitizer_get_symbol");
    if (fn)
        fn(path, module_offset, symbol);
}

void oe_die_ocall()
{
    typedef void (*fn__sanitizer_die)();
    fn__sanitizer_die fn =
        (fn__sanitizer_die)dlsym(RTLD_DEFAULT, "__sanitizer_die");
    if (fn)
        fn();
}

oe_result_t oe_get_symbol_offset_ocall(
    oe_enclave_t* oe_enclave,
    const char* name,
    uint64_t* offset)
{
    bool enclave = false;
    char* path = NULL;
    char kernel_path[PATH_MAX];
    if (oe_enclave)
    {
        enclave = true;
        path = oe_enclave->path;
    }
    else
    {
        if (format_libmystkernel(kernel_path, sizeof(kernel_path)) != 0)
        {
            abort();
        }
        path = kernel_path;
    }

    static std::map<std::string, uint64_t> sym_map;
    static std::map<std::string, uint64_t> kernel_sym_map;
    if (enclave)
    {
        if (sym_map.empty())
        {
            if (!enclave_elf_loaded)
            {
                if (elf64_load(path, &enclave_elf) != 0)
                    return OE_UNEXPECTED;
                if (!enclave_elf.data)
                    return OE_UNEXPECTED;
                enclave_elf_loaded = true;
            }
            
            size_t index = elf_find_shdr(&enclave_elf, ".symtab");
            const elf64_shdr_t* sh = elf64_get_section_header(&enclave_elf, index);
            if (!sh) return OE_UNEXPECTED;

            const elf64_sym_t* symtab = (const elf64_sym_t*)elf_get_section(&enclave_elf, index);
            if (!symtab) return OE_UNEXPECTED;

            size_t n = sh->sh_size / sh->sh_entsize;
            for (size_t i = 1; i < n; i++)
            {
                const elf64_sym_t* p = &symtab[i];
                if (!p || !p->st_name) continue;

                const char* s = elf64_get_string_from_strtab(&enclave_elf, p->st_name);
                if (!s) return OE_UNEXPECTED;
                
                sym_map.insert({s, (uint64_t)p->st_value});
            }
        }
        auto it = sym_map.find(name);
        if (it != sym_map.end())
            *offset = it->second;
    }
    else
    {
        if (kernel_sym_map.empty())
        {
            if (!kernel_elf_loaded)
            {
                if (elf64_load(path, &kernel_elf) != 0)
                    return OE_UNEXPECTED;
                if (!kernel_elf.data)
                    return OE_UNEXPECTED;
                kernel_elf_loaded = true;
            }
            
            size_t index = elf_find_shdr(&kernel_elf, ".symtab");
            const elf64_shdr_t* sh = elf64_get_section_header(&kernel_elf, index);
            if (!sh) return OE_UNEXPECTED;

            const elf64_sym_t* symtab = (const elf64_sym_t*)elf_get_section(&kernel_elf, index);
            if (!symtab) return OE_UNEXPECTED;

            size_t n = sh->sh_size / sh->sh_entsize;
            for (size_t i = 1; i < n; i++)
            {
                const elf64_sym_t* p = &symtab[i];
                if (!p || !p->st_name) continue;

                const char* s = elf64_get_string_from_strtab(&kernel_elf, p->st_name);
                if (!s) return OE_UNEXPECTED;
                
                kernel_sym_map.insert({s, (uint64_t)p->st_value});
            }
        }

        auto it = kernel_sym_map.find(name);
        if (it != kernel_sym_map.end())
            *offset = it->second;
    }


    return (*offset) ? OE_OK : OE_UNEXPECTED;
}

oe_result_t oe_syscall_ocall(
    uint64_t syscall_id,
    uint64_t* return_value,
    void* args)
{
    switch (syscall_id)
    {
        case OE_OCALL_PRRLIMIT64:
        {
            struct prlimit64_args* arg_ptr = (struct prlimit64_args*)args;
            *return_value = (uint64_t)syscall(
                SYS_prlimit64,
                arg_ptr->pid,
                arg_ptr->resource,
                arg_ptr->new_limit,
                arg_ptr->old_limit);
        }
        break;
        case OE_OCALL_GETLIMIT:
        {
            struct getrlimit_args* arg_ptr = (struct getrlimit_args*)args;
            *return_value = (uint64_t)syscall(
                SYS_getrlimit, arg_ptr->resource, arg_ptr->rlim);
        }
        break;
    }

    return OE_OK;
}
