# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

cmake_policy(SET CMP0070 NEW)
set(LIBUNWIND ${OPEN_ENCLAVE_SDK_SRC}/3rdparty/libunwind/libunwind)
set(ARCH "x86_64")
set(PLATFORM_SRC
  ${LIBUNWIND}/src/x86_64/Los-linux.c
  ${CMAKE_CURRENT_SOURCE_DIR}/Gstep.c
  ${CMAKE_CURRENT_SOURCE_DIR}/setcontext.S
)

configure_file(
  ${LIBUNWIND}/include/libunwind-${ARCH}.h
  libunwind.h
  COPYONLY)

configure_file(
  ${LIBUNWIND}/src/${ARCH}/Gstep.c
  Gstep.inc
  COPYONLY)

file(GENERATE OUTPUT config.h CONTENT "/* Empty file */\n")

set(PKG_MAJOR 1)
set(PKG_MINOR 3)
configure_file(
  ${LIBUNWIND}/include/libunwind-common.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/libunwind-common.inc
  COPYONLY)

# configure_file(
#   ${LIBUNWIND}/include/libunwind-dynamic.h
#   ${CMAKE_CURRENT_BINARY_DIR}/libunwind-dynamic.h
#   COPYONLY)

# configure_file(
#   ${LIBUNWIND}/include/dwarf_i.h
#   ${CMAKE_CURRENT_BINARY_DIR}/dwarf_i.h
#   COPYONLY)

# configure_file(
#   ${LIBUNWIND}/include/dwarf.h
#   ${CMAKE_CURRENT_BINARY_DIR}/dwarf.h
#   COPYONLY)

file(COPY ${LIBUNWIND}/include/tdep-${ARCH}/ DESTINATION tdep)

add_library(libunwind STATIC
  # Total 67 items
  ${LIBUNWIND}/src/dwarf/global.c
  ${LIBUNWIND}/src/dwarf/Lexpr.c
  ${LIBUNWIND}/src/dwarf/Lfde.c
  ${LIBUNWIND}/src/dwarf/Lfind_proc_info-lsb.c
  ${LIBUNWIND}/src/dwarf/Lfind_unwind_table.c
  ${LIBUNWIND}/src/dwarf/Lparser.c
  ${LIBUNWIND}/src/dwarf/Lpe.c
  ${LIBUNWIND}/src/mi/_ReadULEB.c
  ${LIBUNWIND}/src/mi/_ReadSLEB.c
  ${LIBUNWIND}/src/mi/backtrace.c
  ${LIBUNWIND}/src/mi/dyn-cancel.c
  ${LIBUNWIND}/src/mi/dyn-info-list.c
  ${LIBUNWIND}/src/mi/dyn-register.c
  ${LIBUNWIND}/src/mi/flush_cache.c
  ${LIBUNWIND}/src/mi/init.c
  ${LIBUNWIND}/src/mi/Ldestroy_addr_space.c
  ${LIBUNWIND}/src/mi/Ldyn-extract.c
  ${LIBUNWIND}/src/mi/Lfind_dynamic_proc_info.c
  ${LIBUNWIND}/src/mi/Lget_accessors.c
  ${LIBUNWIND}/src/mi/Lget_fpreg.c
  ${LIBUNWIND}/src/mi/Lget_proc_info_by_ip.c
  ${LIBUNWIND}/src/mi/Lget_proc_name.c
  ${LIBUNWIND}/src/mi/Lget_reg.c
  ${LIBUNWIND}/src/mi/Lput_dynamic_unwind_info.c
  ${LIBUNWIND}/src/mi/Lset_cache_size.c
  ${LIBUNWIND}/src/mi/Lset_caching_policy.c
  ${LIBUNWIND}/src/mi/Lset_fpreg.c
  ${LIBUNWIND}/src/mi/Lset_reg.c
  ${LIBUNWIND}/src/mi/mempool.c
  ${LIBUNWIND}/src/mi/strerror.c
  ${LIBUNWIND}/src/unwind/Backtrace.c
  ${LIBUNWIND}/src/unwind/DeleteException.c
  ${LIBUNWIND}/src/unwind/FindEnclosingFunction.c
  ${LIBUNWIND}/src/unwind/ForcedUnwind.c
  ${LIBUNWIND}/src/unwind/GetBSP.c
  ${LIBUNWIND}/src/unwind/GetCFA.c
  ${LIBUNWIND}/src/unwind/GetDataRelBase.c
  ${LIBUNWIND}/src/unwind/GetGR.c
  ${LIBUNWIND}/src/unwind/GetIPInfo.c
  ${LIBUNWIND}/src/unwind/GetIP.c
  ${LIBUNWIND}/src/unwind/GetLanguageSpecificData.c
  ${LIBUNWIND}/src/unwind/GetRegionStart.c
  ${LIBUNWIND}/src/unwind/GetTextRelBase.c
  ${LIBUNWIND}/src/unwind/RaiseException.c
  ${LIBUNWIND}/src/unwind/Resume.c
  ${LIBUNWIND}/src/unwind/Resume_or_Rethrow.c
  ${LIBUNWIND}/src/unwind/SetGR.c
  ${LIBUNWIND}/src/unwind/SetIP.c
  ${LIBUNWIND}/src/${ARCH}/getcontext.S
  ${LIBUNWIND}/src/${ARCH}/is_fpreg.c
  ${LIBUNWIND}/src/${ARCH}/Lcreate_addr_space.c
  ${LIBUNWIND}/src/${ARCH}/Lget_save_loc.c
  ${LIBUNWIND}/src/${ARCH}/Lglobal.c
  ${LIBUNWIND}/src/${ARCH}/Linit.c
  ${LIBUNWIND}/src/${ARCH}/Linit_local.c
  ${LIBUNWIND}/src/${ARCH}/Linit_remote.c
  ${LIBUNWIND}/src/${ARCH}/Lget_proc_info.c
  ${LIBUNWIND}/src/${ARCH}/Lregs.c
  ${LIBUNWIND}/src/${ARCH}/Lresume.c
  ${LIBUNWIND}/src/${ARCH}/Lstash_frame.c
  ${LIBUNWIND}/src/${ARCH}/Ltrace.c
  ${LIBUNWIND}/src/${ARCH}/regname.c
  ${LIBUNWIND}/src/os-linux.c
  ${LIBUNWIND}/src/elf64.c
  ${PLATFORM_SRC}

  # Add dependency to libunwind.h generation.
  ${CMAKE_CURRENT_BINARY_DIR}/libunwind.h)

# maybe_build_using_clangw(libunwind)

# set_source_files_properties(Gstep.c PROPERTIES COMPILE_FLAGS "-Werror")
# set_source_files_properties(setcontext.S PROPERTIES COMPILE_FLAGS "-Werror")

target_compile_options(libunwind PRIVATE
  -Wno-error
  -Wno-macro-redefined
  -include ${CMAKE_CURRENT_SOURCE_DIR}/stubs.h)

target_compile_definitions(libunwind PRIVATE
  HAVE_ELF_H
  HAVE_ENDIAN_H
  HAVE_LINK_H
  _GNU_SOURCE
  UNW_LOCAL_ONLY=1
  #__x86_64__
  HAVE_DL_ITERATE_PHDR
  PACKAGE_STRING=\"libunwind-1.3\"
  PACKAGE_BUGREPORT=\"unwind.org\")

# target_link_libraries(libunwind PUBLIC oelibc)

target_include_directories(libunwind PRIVATE
  ${LIBUNWIND}/include
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}/tdep
  ${LIBUNWIND}/src
  ${LIBUNWIND}/src/${ARCH}
  )
