if(CONFIGURE_CMAKE_)
  return()
endif() # CONFIGURE_CMAKE_
set(CONFIGURE_CMAKE_ 1)

include(FindGit)
include(FindPerl)
include(FindThreads)

include("${PROJ_ROOT}/cmake/defaults.cmake")
include("${PROJ_ROOT}/cmake/optimization.cmake")
include("${PROJ_ROOT}/cmake/compiler_flags.cmake")
include("${PROJ_ROOT}/cmake/compiler_tests.cmake")

# Generate the user config settings.
list(APPEND build_vars ${CONFIG_VARS} ${OPTION_VARS})
foreach(cache_var ${build_vars})
  get_property(cache_var_helpstring CACHE ${cache_var} PROPERTY HELPSTRING)
  if("${cache_var_helpstring}" STREQUAL "${cmake_cmdline_helpstring}")
    set(CMAKE_CONFIG "${CMAKE_CONFIG} -D${cache_var}=${${cache_var}}")
  endif()
endforeach()
string(STRIP "${CMAKE_CONFIG}" CMAKE_CONFIG)

# Detect target CPU.
if(NOT TARGET_CPU)
  if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "AMD64" OR
     "${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86_64")
    if(${CMAKE_SIZEOF_VOID_P} EQUAL 4)
      set(TARGET_CPU "x86")
    elseif(${CMAKE_SIZEOF_VOID_P} EQUAL 8)
      set(TARGET_CPU "x86_64")
    else()
      message(FATAL_ERROR
                "--- Unexpected pointer size (${CMAKE_SIZEOF_VOID_P}) for\n"
                "      CMAKE_SYSTEM_NAME=${CMAKE_SYSTEM_NAME}\n"
                "      CMAKE_SYSTEM_PROCESSOR=${CMAKE_SYSTEM_PROCESSOR}\n"
                "      CMAKE_GENERATOR=${CMAKE_GENERATOR}\n")
    endif()
  elseif("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "i386" OR
         "${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86")
    set(TARGET_CPU "x86")
  elseif("${CMAKE_SYSTEM_PROCESSOR}" MATCHES "^arm" OR
         "${CMAKE_SYSTEM_PROCESSOR}" MATCHES "^mips")
    set(TARGET_CPU "${CMAKE_SYSTEM_PROCESSOR}")
  elseif("${CMAKE_SYSTEM_PROCESSOR}" MATCHES "aarch64")
    set(TARGET_CPU "arm64")
  elseif("${CMAKE_SYSTEM_PROCESSOR}" MATCHES "^ppc")
    set(TARGET_CPU "ppc")
  else()
    message(WARNING "The architecture ${CMAKE_SYSTEM_PROCESSOR} is not "
                    "supported, falling back to the generic target")
	    set(TARGET_CPU "generic")
	  endif()
	endif()

	if(CMAKE_TOOLCHAIN_FILE) # Add toolchain file to config string.
	  if(IS_ABSOLUTE "${CMAKE_TOOLCHAIN_FILE}")
	    file(RELATIVE_PATH toolchain_path "${CONFIG_DIR}"
			       "${CMAKE_TOOLCHAIN_FILE}")
	  else()
	    set(toolchain_path "${CMAKE_TOOLCHAIN_FILE}")
	  endif()
	  set(toolchain_string "-DCMAKE_TOOLCHAIN_FILE=\\\"${toolchain_path}\\\"")
	  set(CMAKE_CONFIG "${toolchain_string} ${CMAKE_CONFIG}")
	else()

	  # Add detected CPU to the config string.
	  set(CMAKE_CONFIG "-DTARGET_CPU=${TARGET_CPU} ${CMAKE_CONFIG}")
endif()
set(CMAKE_CONFIG "-G \\\"${CMAKE_GENERATOR}\\\" ${CMAKE_CONFIG}")
file(RELATIVE_PATH source_path "${CONFIG_DIR}" "${PROJ_ROOT}")
set(CMAKE_CONFIG "cmake ${source_path} ${CMAKE_CONFIG}")
string(STRIP "${CMAKE_CONFIG}" CMAKE_CONFIG)

message("--- cpu_config: Detected CPU: ${TARGET_CPU}")
set(TARGET_SYSTEM ${CMAKE_SYSTEM_NAME})

if("${CMAKE_BUILD_TYPE}" MATCHES "Deb")
  set(CONFIG_DEBUG 1)
endif()

if(BUILD_SHARED_LIBS)
  set(CONFIG_PIC 1)
  set(CONFIG_SHARED 1)
  set(CONFIG_STATIC 0)
endif()

if(NOT MSVC)
  if(CONFIG_PIC)

    # TODO: clang needs -pie in CMAKE_EXE_LINKER_FLAGS for this to work.
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    if("${TARGET_SYSTEM}" STREQUAL "Linux" AND "${TARGET_CPU}" MATCHES
       "^armv[78]")
      set(MY_AS_FLAGS ${MY_AS_FLAGS} --defsym PIC=1)
    else()
      set(MY_AS_FLAGS ${MY_AS_FLAGS} -DPIC)
    endif()
  endif()
endif()

if("${TARGET_CPU}" STREQUAL "x86" OR "${TARGET_CPU}" STREQUAL "x86_64")
  find_program(AS_EXECUTABLE yasm $ENV{YASM_PATH})
  if(NOT AS_EXECUTABLE OR ENABLE_NASM)
    unset(AS_EXECUTABLE CACHE)
    find_program(AS_EXECUTABLE nasm $ENV{NASM_PATH})
    if(AS_EXECUTABLE)
      test_nasm()
    endif()
  endif()

  if(NOT AS_EXECUTABLE)
    message(FATAL_ERROR
              "Unable to find assembler. Install 'yasm' or 'nasm.' "
              "To build without optimizations, add -DTARGET_CPU=generic to "
              "your cmake command line.")
  endif()
  get_asm_obj_format("objformat")
  set(MY_AS_FLAGS -f ${objformat} ${MY_AS_FLAGS})
  string(STRIP "${MY_AS_FLAGS}" MY_AS_FLAGS)
elseif("${TARGET_CPU}" MATCHES "arm")
  if("${TARGET_SYSTEM}" STREQUAL "Darwin")
    set(AS_EXECUTABLE as)
    set(MY_AS_FLAGS -arch ${TARGET_CPU} -isysroot ${CMAKE_OSX_SYSROOT})
  elseif("${TARGET_SYSTEM}" STREQUAL "Linux")
    if(NOT AS_EXECUTABLE)
      set(AS_EXECUTABLE as)
    endif()
  elseif("${TARGET_SYSTEM}" STREQUAL "Windows")
    if(NOT AS_EXECUTABLE)
      set(AS_EXECUTABLE ${CMAKE_C_COMPILER} -c -mimplicit-it=always)
    endif()
  endif()
  if(NOT AS_EXECUTABLE)
    message(FATAL_ERROR
              "Unknown assembler for: ${TARGET_CPU}-${TARGET_SYSTEM}")
  endif()

  string(STRIP "${MY_AS_FLAGS}" MY_AS_FLAGS)
endif()

if(CONFIG_ANALYZER)
  include(FindwxWidgets)
  find_package(wxWidgets REQUIRED adv base core)
  include(${wxWidgets_USE_FILE})
endif()

if(NOT MSVC AND CMAKE_C_COMPILER_ID MATCHES "GNU\|Clang")
  set(CONFIG_GCC 1)
endif()

if(CONFIG_GCOV)
  message("--- Testing for CONFIG_GCOV support.")
  require_linker_flag("-fprofile-arcs -ftest-coverage")
  require_compiler_flag("-fprofile-arcs -ftest-coverage" YES)
endif()

if(CONFIG_GPROF)
  message("--- Testing for CONFIG_GPROF support.")
  require_compiler_flag("-pg" YES)
endif()

if("${TARGET_SYSTEM}" MATCHES "Darwin\|Linux\|Windows")
  set(CONFIG_OS_SUPPORT 1)
endif()

# The default _WIN32_WINNT value in MinGW is 0x0502 (Windows XP with SP2). Set
# it to 0x0601 (Windows 7).
if("${TARGET_SYSTEM}" STREQUAL "Windows")
  add_compiler_flag_if_supported("-D_WIN32_WINNT=0x0601")
endif()

# Test compiler support.
get_inline("INLINE")

# Don't just check for pthread.h, but use the result of the full pthreads
# including a linking check in FindThreads above.
set(HAVE_PTHREAD_H ${CMAKE_USE_PTHREADS_INIT})
check_source_compiles("unistd_check" "#include <unistd.h>" HAVE_UNISTD_H)

if(NOT MSVC)
  push_var(CMAKE_REQUIRED_LIBRARIES "m")
  check_c_compiles(
    "fenv_check"
    "#define _GNU_SOURCE
                        #include <fenv.h>
                        void unused(void) {
                          (void)unused;
                          (void)feenableexcept(FE_DIVBYZERO | FE_INVALID);
                        }"
    HAVE_FEXCEPT)
  pop_var(CMAKE_REQUIRED_LIBRARIES)
endif()

if("${TARGET_CPU}" MATCHES "^arm")
  set(ARCH_ARM 1)

  if(ENABLE_NEON)
    set(HAVE_NEON 1)
  else()
    set(HAVE_NEON 0)
  endif()
elseif("${TARGET_CPU}" MATCHES "^mips")
  set(ARCH_MIPS 1)

  if("${TARGET_CPU}" STREQUAL "mips32")
    set(HAVE_MIPS32 1)
  elseif("${TARGET_CPU}" STREQUAL "mips64")
    set(HAVE_MIPS64 1)
  endif()

elseif("${TARGET_CPU}" MATCHES "ppc")
  set(ARCH_PPC 1)

  if(ENABLE_VSX)
    set(HAVE_VSX 1)
  else()
    set(HAVE_VSX 0)
  endif()
elseif("${TARGET_CPU}" MATCHES "^x86")
  if("${TARGET_CPU}" STREQUAL "x86")
    set(ARCH_X86 1)
  elseif("${TARGET_CPU}" STREQUAL "x86_64")
    set(ARCH_X86_64 1)
  endif()

  set(X86_FLAVORS "MMX;SSE;SSE2;SSE3;SSSE3;SSE4_1;SSE4_2;AVX;AVX2")
  foreach(flavor ${X86_FLAVORS})
    if(ENABLE_${flavor} AND NOT disable_remaining_flavors)
      set(HAVE_${flavor} 1)
    else()
      set(disable_remaining_flavors 1)
      set(HAVE_${flavor} 0)
      string(TOLOWER ${flavor} flavor)
    endif()
  endforeach()
endif()


if(ENABLE_CCACHE)
  set_compiler_launcher(ENABLE_CCACHE ccache)
endif()

if(ENABLE_DISTCC)
  set_compiler_launcher(ENABLE_DISTCC distcc)
endif()

if(ENABLE_GOMA)
  set_compiler_launcher(ENABLE_GOMA gomacc)
endif()

# Test compiler flags.
if(MSVC)
  add_compiler_flag_if_supported("/W3")

  # Disable MSVC warnings that suggest making code non-portable.
  add_compiler_flag_if_supported("/wd4996")
  if(ENABLE_WERROR)
    add_compiler_flag_if_supported("/WX")
  endif()
else()
  require_c_flag("-std=c99" YES)
  require_cxx_flag_nomsvc("-std=c++11" YES)
  add_compiler_flag_if_supported("-Wall")
  add_compiler_flag_if_supported("-Wdisabled-optimization")
  add_compiler_flag_if_supported("-Wextra")
  add_compiler_flag_if_supported("-Wfloat-conversion")
  add_compiler_flag_if_supported("-Wimplicit-function-declaration")
  add_compiler_flag_if_supported("-Wlogical-op")
  add_compiler_flag_if_supported("-Wpointer-arith")
  add_compiler_flag_if_supported("-Wsign-compare")
  add_compiler_flag_if_supported("-Wstring-conversion")
  add_compiler_flag_if_supported("-Wtype-limits")
  add_compiler_flag_if_supported("-Wuninitialized")
  add_compiler_flag_if_supported("-Wunused")
  add_compiler_flag_if_supported("-Wvla")

  if(CMAKE_C_COMPILER_ID MATCHES "GNU" AND "${SANITIZE}" MATCHES
     "address|undefined")

    # This combination has more stack overhead, so we account for it by
    # providing higher stack limit than usual.
    add_c_flag_if_supported("-Wstack-usage=170000")
    add_cxx_flag_if_supported("-Wstack-usage=270000")
  else()
    add_c_flag_if_supported("-Wstack-usage=100000")
    add_cxx_flag_if_supported("-Wstack-usage=240000")
  endif()

  # TODO: this can be added as a cxx flags for test/*.cc only, avoid third_party.
  add_c_flag_if_supported("-Wshorten-64-to-32")

  # Add -Wshadow only for C files to avoid massive gtest warning spam.
  add_c_flag_if_supported("-Wshadow")

  # Add -Wundef only for C files to avoid massive gtest warning spam.
  add_c_flag_if_supported("-Wundef")

  # Quiet gcc 6 vs 7 abi warnings:
  # https://gcc.gnu.org/bugzilla/show_bug.cgi?id=77728
  if("${TARGET_CPU}" MATCHES "arm")
    add_cxx_flag_if_supported("-Wno-psabi")
  endif()

  if(ENABLE_WERROR)
    add_compiler_flag_if_supported("-Werror")
  endif()

  if("${CMAKE_BUILD_TYPE}" MATCHES "Rel")
    add_compiler_flag_if_supported("-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0")
  endif()
  add_compiler_flag_if_supported("-D_LARGEFILE_SOURCE")
  add_compiler_flag_if_supported("-D_FILE_OFFSET_BITS=64")
endif()

set(LIB_LINK_TYPE PUBLIC)
if(EMSCRIPTEN)

  # Avoid CMake generation time errors resulting from collisions with the form
  # of target_link_libraries() used by Emscripten.cmake.
  unset(LIB_LINK_TYPE)
endif()

# Read the current git hash.
find_package(Git)
if(NOT GIT_FOUND)
  message("--- Git missing, version will be read from CHANGELOG.")
endif()

