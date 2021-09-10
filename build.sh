#!/bin/bash
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set -e
ulimit -n 4096

export MYSTIK_SEC_ROOT=${PWD}
export MYSTIK_SEC_BUILD=${MYSTIK_SEC_ROOT}/build
export MYSTIK_SEC_TOOLS=${MYSTIK_SEC_ROOT}/build/tools
export MYSTIK_SRC_ROOT=${MYSTIK_SEC_ROOT}/sut/mystikos
export MYSTIK_3RDPARTY=${MYSTIK_SEC_ROOT}/3rdparty
export MYSTIK_SEC_FUZZING_BUILD=${MYSTIK_SEC_BUILD}/fuzzing_build

# export OE_LLVM_URL="https://github.com/openenclave/openenclave-security/releases/download/v1.0/oe-llvm-1.0.zip"
export OE_LLVM_URL="/home/ragava/Desktop/labs/oe-llvm/build/oe-llvm-1.0.zip"
export CLANG=${MYSTIK_SEC_TOOLS}/oe-llvm-1.0/bin/clang
export CLANG_CPP=${MYSTIK_SEC_TOOLS}/oe-llvm-1.0/bin/clang++

export INTEL_SGX_SDK="https://download.01.org/intel-sgx/sgx-linux/2.13/distro/ubuntu18.04-server/sgx_linux_x64_sdk_2.13.100.4.bin"
export INTEL_SGX_SDK_PACKAGE="sgx_linux_x64_sdk_2.13.100.4.bin"

CLEAN=0
INSTALL_DEPENDS=0
BUILD_INTEL_SGX_PSW=0
for i in "$@"; do
    case $i in
    -c | --clean)
        CLEAN=1
        ;;
    esac
    case $i in
    -d | --depends)
        INSTALL_DEPENDS=1
        ;;
    esac
    case $i in
    -i | --intelsdk)
        BUILD_INTEL_SGX_PSW=1
        ;;
    esac
done

# Intel PSW build dependencies
if [[ $INSTALL_DEPENDS -eq 1 ]]; then
    sudo apt-get update
    sudo apt-get install -y build-essential ocaml ocamlbuild automake autoconf libtool wget \
        libssl-dev perl libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper reprepro unzip
fi

[[ ${CLEAN} -eq 1 ]] && rm -rf "${MYSTIK_SEC_BUILD}"
[[ ! -d "${MYSTIK_SEC_BUILD}" ]] && mkdir -p "${MYSTIK_SEC_BUILD}"

if [[ ! -d "${MYSTIK_SEC_TOOLS}" ]]; then
    mkdir -p "${MYSTIK_SEC_TOOLS}"
    pushd "${MYSTIK_SEC_TOOLS}"
    # wget "${OE_LLVM_URL}"
    cp "${OE_LLVM_URL}" ./
    unzip oe-llvm-1.0.zip
    popd
fi

MAKE_THREADS=$(nproc)

# Building debug version of Intel PSW.
if [[ ${BUILD_INTEL_SGX_PSW} -eq 1 ]]; then
    if [[ ! -d "/opt/intel/sgxsdk" ]]; then
        pushd "${MYSTIK_SEC_TOOLS}"
        wget "${INTEL_SGX_SDK}"
        chmod +x ./"${INTEL_SGX_SDK_PACKAGE}"
        sudo ./"${INTEL_SGX_SDK_PACKAGE}" <<EOF
no
/opt/intel
EOF
        popd
    fi

    pushd "${MYSTIK_3RDPARTY}"
    make -C linux-sgx clean all
    make -C linux-sgx preparation
    make -C linux-sgx psw DEBUG=1 -j ${MAKE_THREADS}
    popd
fi

pushd "${MYSTIK_SRC_ROOT}"
sudo make clean
sudo make MYST_PRODUCT_BUILD=1 -j ${MAKE_THREADS}
popd

# # Building OE in debug mode and instrumented with OE-LLVM sanitizers.
# if [[ ! -d "${OE_INSTRUMENTED_BUILD}" ]]; then
#     mkdir -p "${OE_INSTRUMENTED_BUILD}"
#     mkdir -p "${OE_INSTRUMENTED_INSTALL_PREFIX}"
#     pushd "${OE_INSTRUMENTED_BUILD}"
#     cmake "${OE_SRC_ROOT}" -GNinja \
#         -DENABLE_FUZZING=ON \
#         -DBUILD_OEUTIL_TOOL=OFF \
#         -DBUILD_TESTS=OFF \
#         -DCMAKE_C_COMPILER="${CLANG}" \
#         -DCMAKE_CXX_COMPILER="${CLANG_CPP}" \
#         -DCMAKE_BUILD_TYPE=Debug \
#         -DCMAKE_C_FLAGS_DEBUG="-O0 -g" \
#         -DCMAKE_CXX_FLAGS_DEBUG="-O0 -g" \
#         -DUSE_DEBUG_MALLOC=OFF \
#         -DCMAKE_INSTALL_PREFIX="${OE_INSTRUMENTED_INSTALL_PREFIX}"
#     ninja install -j ${MAKE_THREADS}
#     popd
# fi

# # Building fuzzer targets with instrumented OE-SDK.
# rm -rf "${OE_SEC_FUZZING_BUILD}"
# mkdir -p "${OE_SEC_FUZZING_BUILD}"
# pushd "${OE_SEC_FUZZING_BUILD}"
# cmake "${OE_SEC_ROOT}" -GNinja \
#     -DCMAKE_BUILD_TYPE=Debug \
#     -DCMAKE_C_FLAGS_DEBUG="-O0 -g" \
#     -DCMAKE_CXX_FLAGS_DEBUG="-O0 -g" \
#     -DCMAKE_C_COMPILER="${CLANG}" \
#     -DCMAKE_CXX_COMPILER="${CLANG_CPP}" \
#     -DCMAKE_PREFIX_PATH="${OE_INSTRUMENTED_INSTALL_PREFIX}"
# ninja -j ${MAKE_THREADS}
# popd

# rm -rf "${OE_SEC_SYSCALLER_BUILD}"
# mkdir -p "${OE_SEC_SYSCALLER_BUILD}"
# pushd "${OE_SEC_SYSCALLER_BUILD}"
# cmake "${OE_SEC_SYSCALLER_SRC_ROOT}" -GNinja \
#     -DCMAKE_BUILD_TYPE=Debug \
#     -DCMAKE_C_FLAGS_DEBUG="-O0 -g" \
#     -DCMAKE_CXX_FLAGS_DEBUG="-O0 -g" \
#     -DCMAKE_C_COMPILER="gcc" \
#     -DCMAKE_CXX_COMPILER="g++"
# ninja -j ${MAKE_THREADS}
# popd

