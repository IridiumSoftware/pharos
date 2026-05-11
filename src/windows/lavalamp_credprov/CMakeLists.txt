# CMakeLists.txt — Windows Credential Provider Filter build.
#
# Build (from a Visual Studio 2022 x64 native tools command prompt):
#   cmake -B build -A x64 -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%/scripts/buildsystems/vcpkg.cmake
#   cmake --build build --config Release
#
# Output: build/Release/LavaLampCredentialProvider.dll
#
# OpenSSL is pinned via vcpkg.json in this directory.

cmake_minimum_required(VERSION 3.20)
project(LavaLampCredentialProvider LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build target: Windows-only.
if(NOT WIN32)
    message(FATAL_ERROR
        "LavaLampCredentialProvider is Windows-only; CMake "
        "is running on a non-Windows host. Cross-compilation "
        "from macOS / Linux is out of scope for v0.0.8 — "
        "build on a Windows host with Visual Studio 2022.")
endif()

find_package(OpenSSL 3.0 REQUIRED)

# Transport selection. AF_UNIX is the default (Win10 build 17063+).
# Override at configure time with -DLL_IPC_TRANSPORT=LL_IPC_NAMED_PIPE.
set(LL_IPC_TRANSPORT "LL_IPC_AF_UNIX" CACHE STRING
    "IPC transport: LL_IPC_AF_UNIX or LL_IPC_NAMED_PIPE")

add_library(LavaLampCredentialProvider SHARED
    dllmain.cpp
    LavaLampCredentialProviderFilter.cpp
    LavaLampIPC.cpp
    LavaLampCredentialProvider.def
    Guid.h
    LavaLampCredentialProviderFilter.h
    LavaLampIPC.h)

target_compile_definitions(LavaLampCredentialProvider PRIVATE
    UNICODE _UNICODE
    LL_IPC_TRANSPORT=${LL_IPC_TRANSPORT})

target_compile_options(LavaLampCredentialProvider PRIVATE
    /W4 /WX
    /wd4995  # deprecated EVP_PKEY_assign_EC_KEY in OpenSSL 3
    /wd4996) # other deprecated-API warnings

target_link_libraries(LavaLampCredentialProvider PRIVATE
    OpenSSL::SSL OpenSSL::Crypto)

# Authenticode signing is left to the operator. ad-hoc signing
# is sufficient for installation on machines where the user has
# administrative access. Production deployments should use a
# code-signing certificate; see README.md §Production deployment.
