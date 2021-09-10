// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifdef __GNUC__

// #include <openenclave/enclave.h>
#include <stdarg.h>
#include <stdio.h>

// GCC sometimes replaces printf() calls with __printf_chk() calls. In glibc
// this function sets the output stream's _IO_FLAGS2_FORTIFY flag, which
// causes glibc to perform various checks on the output stream. Since MUSL has
// no equivalent flag, this implementation simply calls vfprintf().
int __printf_chk(int flag, const char* format, ...)
{
    va_list ap;

    // OE_UNUSED(flag);

    va_start(ap, format);
    int ret = vfprintf(stdout, format, ap);
    va_end(ap);

    return ret;
}

#endif // __GNUC__
