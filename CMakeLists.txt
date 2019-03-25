# http://derekmolloy.ie/hello-world-introductions-to-cmake/
cmake_minimum_required(VERSION 3.5)
project(TinyTls C CXX ASM)
set(CMAKE_BUILD_TYPE Release)
#set(CMAKE_BUILD_TYPE RelWithDebInfo)

set(PROJ_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
set(CONFIG_DIR "${CMAKE_CURRENT_BINARY_DIR}")
include("${PROJ_ROOT}/cmake/cpu_config.cmake")

if("${TARGET_CPU}" STREQUAL "x86_64")
set (TARGET_PLATFORM32 "i386")
set (TARGET_PLATFORM64 "x86_64")
else("${TARGET_CPU}" STREQUAL "x86_64")
set (TARGET_PLATFORM ${TARGET_CPU})
endif("${TARGET_CPU}" STREQUAL "x86_64")

message("Target CPU is ${TARGET_CPU}")

if("${TARGET_CPU}" STREQUAL "x86_64")
message("Platform is set to ${TARGET_PLATFORM32} and ${TARGET_PLATFORM64}")
else("${TARGET_CPU}" STREQUAL "x86_64")
message("Platform is set to ${TARGET_PLATFORM}")
endif("${TARGET_CPU}" STREQUAL "x86_64")

SET(ASM_OPTIONS "-x assembler-with-cpp")
SET(CMAKE_ASM_FLAGS "${CFLAGS} ${ASM_OPTIONS}" )

set_source_files_properties(*.s PROPERTIES COMPILE_FLAGS "-x assembler-with-cpp")

# Generic compilation options
if(MSVC)
  add_definitions(-DWIN32_LEAN_AND_MEAN)
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
  add_definitions(-D_SCL_SECURE_NO_WARNINGS)
  add_definitions(-D_ENABLE_EXTENDED_ALIGNED_STORAGE)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /EHsc")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /bigobj")
  if(USE_MSVC_MT)
    foreach(flag_var
        CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
        CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO)
      if(${flag_var} MATCHES "/MD")
        string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
      endif(${flag_var} MATCHES "/MD")
    endforeach(flag_var)
  endif()
else(MSVC)
  include(CheckCXXCompilerFlag)
  check_cxx_compiler_flag("-std=c++11"    SUPPORT_CXX11)
  if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    add_compile_options(-O0 -Wall -fPIC -fms-extensions -std=c++11)
  else()
    set(CMAKE_C_FLAGS "-O2 -Wall -fPIC -fms-extensions ${CMAKE_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "-O2 -Wall -fPIC -fms-extensions -std=c++11 ${CMAKE_CXX_FLAGS}")
  endif ()
  if (CMAKE_CXX_COMPILER_ID MATCHES "GNU" AND
      CMAKE_CXX_COMPILER_VERSION VERSION_GREATER 7.0)
    set(CMAKE_CXX_FLAGS "-faligned-new ${CMAKE_CXX_FLAGS}")
  endif()
endif(MSVC)
 
#Bring the included headers into the project
include_directories(
    include
    include/cert
    include/net
    include/rsa
    include/sha
    include/ecc
    include/aes
    include/cha
    include/ssl
    test
    )
 
#Can manually add the sources using the set command as follows:
#set(SOURCES src/mainapp.cpp src/Student.cpp)
 
#However, the file(GLOB...) allows for wildcard additions:
#file(GLOB SOURCES "src/*.cpp")
#file(GLOB ASM_SOURCES "src/*.s")

set(PROJECT_SRC_DIR "src")

if("${TARGET_CPU}" STREQUAL "x86_64")
set(PLATFORM32_SRC
    src/${TARGET_PLATFORM32}/clock.s
    )

set(PLATFORM64_SRC
    src/${TARGET_PLATFORM64}/clock.s
    )
else("${TARGET_CPU}" STREQUAL "x86_64")
set(PLATFORM_SRC
    src/${TARGET_PLATFORM}/clock.s
    )
endif("${TARGET_CPU}" STREQUAL "x86_64")

set(ECC_SRC
    src/ecc/ecc.cpp
    src/ecc/ecc_dh.cpp
    src/ecc/ecc_fold.cpp
    src/ecc/ecc_k256.cpp
    src/ecc/ecc_p256.cpp
    src/ecc/ecc_sign.cpp
    src/ecc/ecc_verify.cpp
    src/ecc/ecc_x25519.cpp
    )

set(AES_SRC
    src/aes/aes128.cpp
    )

set(CC20_SRC
    src/cha/chacha20.cpp
    )

set(RSA_SRC
    src/rsa/BN.c
    )

set(SHA_SRC
    src/sha/sha1.c
    src/sha/sha256.c
    src/sha/sha512.c
    src/sha/hmac.cpp
    src/sha/hkdf.cpp
    src/sha/ssa.cpp
    src/sha/ripemd.c
    src/sha/ripemd160.cpp
    src/sha/base58.cpp
    )

set(CERT_SRC
    src/cert/cert.c
    src/cert/oid.c
    src/cert/asn.cpp
    src/cert/x509.cpp
    src/cert/cert_gen.cpp
    )

set(UTIL_SRC
    src/net/TcpSock.cpp
    src/net/TcpSockLinux.cpp
    src/net/dns.cpp
    src/endian.c
    src/cipher.c
    )

set(SSL_SRC
    src/ssl/TlsFactory.cpp
    src/ssl/TinyTls.cpp
    )

set(TEST_SRC
    test/testMain.cpp
    test/aes_test.cpp
    test/ecc_test.cpp
    test/p256_test.cpp
    test/rsa_test.c
    test/cert_test.cpp
    test/certgen_test.cpp
    test/net_test.cpp
    test/MockSock.cpp
    test/rfc8448_test.cpp
    test/certSamples.c
    )

#Generate the shared library from the sources
if("${TARGET_CPU}" STREQUAL "x86_64")
add_library(crypts32 SHARED ${ECC_SRC} ${AES_SRC} ${CC20_SRC} ${SHA_SRC} ${RSA_SRC} ${SSL_SRC} ${CERT_SRC} ${UTIL_SRC} ${os})
add_library(crypts64 SHARED ${ECC_SRC} ${AES_SRC} ${CC20_SRC} ${SHA_SRC} ${RSA_SRC} ${SSL_SRC} ${CERT_SRC} ${UTIL_SRC} ${os})
else("${TARGET_CPU}" STREQUAL "x86_64")
add_library(crypts SHARED ${ECC_SRC} ${AES_SRC} ${CC20_SRC} ${SHA_SRC} ${RSA_SRC} ${SSL_SRC} ${CERT_SRC} ${UTIL_SRC} ${os})
endif("${TARGET_CPU}" STREQUAL "x86_64")

#Generate the static library from the sources
if("${TARGET_CPU}" STREQUAL "x86_64")
add_library(cryptc32 STATIC ${ECC_SRC} ${AES_SRC} ${CC20_SRC} ${SHA_SRC} ${RSA_SRC} ${SSL_SRC} ${CERT_SRC} ${UTIL_SRC} ${os})
add_library(cryptc64 STATIC ${ECC_SRC} ${AES_SRC} ${CC20_SRC} ${SHA_SRC} ${RSA_SRC} ${SSL_SRC} ${CERT_SRC} ${UTIL_SRC} ${os})
else("${TARGET_CPU}" STREQUAL "x86_64")
add_library(cryptc STATIC ${ECC_SRC} ${AES_SRC} ${CC20_SRC} ${SHA_SRC} ${RSA_SRC} ${SSL_SRC} ${CERT_SRC} ${UTIL_SRC} ${os})
endif("${TARGET_CPU}" STREQUAL "x86_64")

if("${TARGET_CPU}" STREQUAL "x86_64")
set_target_properties(crypts32 PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32 -lpthread")
set_target_properties(crypts64 PROPERTIES COMPILE_FLAGS "-m64" LINK_FLAGS "-m64 -lpthread")
set_target_properties(cryptc32 PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32 -lpthread")
set_target_properties(cryptc64 PROPERTIES COMPILE_FLAGS "-m64" LINK_FLAGS "-m64 -lpthread")
endif("${TARGET_CPU}" STREQUAL "x86_64")

#For the shared library:
if("${TARGET_CPU}" STREQUAL "x86_64")
set ( CRYPTS32_LIB crypts32.so )
set ( CRYPTS64_LIB crypts64.so )
else("${TARGET_CPU}" STREQUAL "x86_64")
set ( CRYPTS_LIB crypts.so )
endif("${TARGET_CPU}" STREQUAL "x86_64")

link_directories( ./build )
 
#For the static library:
if("${TARGET_CPU}" STREQUAL "x86_64")
set ( CRYPTC32_LIB cryptc32.a )
set ( CRYPTC64_LIB cryptc64.a )
else("${TARGET_CPU}" STREQUAL "x86_64")
set ( CRYPTC_LIB cryptc.a )
endif("${TARGET_CPU}" STREQUAL "x86_64")

link_directories( ./build )

if("${TARGET_CPU}" STREQUAL "x86_64")
add_executable(ctest32 ${TEST_SRC} ${PLATFORM32_SRC})
add_executable(ctest64 ${TEST_SRC} ${PLATFORM64_SRC})
add_executable(stest32 ${TEST_SRC} ${PLATFORM32_SRC})
add_executable(stest64 ${TEST_SRC} ${PLATFORM64_SRC})
else("${TARGET_CPU}" STREQUAL "x86_64")
add_executable(ctest ${TEST_SRC} ${PLATFORM_SRC})
add_executable(stest ${TEST_SRC} ${PLATFORM_SRC})
endif("${TARGET_CPU}" STREQUAL "x86_64")

if("${TARGET_CPU}" STREQUAL "x86_64")
set_target_properties(ctest32 PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
set_target_properties(ctest64 PROPERTIES COMPILE_FLAGS "-m64" LINK_FLAGS "-m64")
set_target_properties(stest32 PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
set_target_properties(stest64 PROPERTIES COMPILE_FLAGS "-m64" LINK_FLAGS "-m64")
endif("${TARGET_CPU}" STREQUAL "x86_64")

if("${TARGET_CPU}" STREQUAL "x86_64")
target_link_libraries(ctest32 ${CRYPTC32_LIB} -lpthread)
target_link_libraries(ctest64 ${CRYPTC64_LIB} -lpthread)
target_link_libraries(stest32 ${CRYPTS32_LIB} -lpthread)
target_link_libraries(stest64 ${CRYPTS64_LIB} -lpthread)
else("${TARGET_CPU}" STREQUAL "x86_64")
target_link_libraries(ctest ${CRYPTC_LIB} -lpthread)
target_link_libraries(stest ${CRYPTS_LIB} -lpthread)
endif("${TARGET_CPU}" STREQUAL "x86_64")

