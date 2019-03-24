include("${PROJ_ROOT}/cmake/util.cmake")

# This file sets default values for project configuration variables. All config
# variables are added to CMake variable cache via macros provided in util.cmake.

# The variables in this section of the file are detected at configuration time,
# but can be overridden via the use of CONFIG_* and ENABLE_* values also defined
# in this file.

detect_var(INLINE "" STRING "Sets INLINE value for current target.")

# CPUs.
detect_var(ARCH_ARM 0 NUMBER "Enables ARM architecture.")
detect_var(ARCH_MIPS 0 NUMBER "Enables MIPS architecture.")
detect_var(ARCH_PPC 0 NUMBER "Enables PPC architecture.")
detect_var(ARCH_X86 0 NUMBER "Enables X86 architecture.")
detect_var(ARCH_X86_64 0 NUMBER "Enables X86_64 architecture.")

# ARM feature flags.
detect_var(HAVE_NEON 0 NUMBER "Enables NEON intrinsics optimizations.")

# MIPS feature flags.
detect_var(HAVE_DSPR2 0 NUMBER "Enables DSPR2 optimizations.")
detect_var(HAVE_MIPS32 0 NUMBER "Enables MIPS32 optimizations.")
detect_var(HAVE_MIPS64 0 NUMBER "Enables MIPS64 optimizations. ")
detect_var(HAVE_MSA 0 NUMBER "Enables MSA optimizations.")

# PPC feature flags.
detect_var(HAVE_VSX 0 NUMBER "Enables VSX optimizations.")

# x86/x86_64 feature flags.
detect_var(HAVE_AVX 0 NUMBER "Enables AVX optimizations.")
detect_var(HAVE_AVX2 0 NUMBER "Enables AVX2 optimizations.")
detect_var(HAVE_MMX 0 NUMBER "Enables MMX optimizations. ")
detect_var(HAVE_SSE 0 NUMBER "Enables SSE optimizations.")
detect_var(HAVE_SSE2 0 NUMBER "Enables SSE2 optimizations.")
detect_var(HAVE_SSE3 0 NUMBER "Enables SSE3 optimizations.")
detect_var(HAVE_SSE4_1 0 NUMBER "Enables SSE 4.1 optimizations.")
detect_var(HAVE_SSE4_2 0 NUMBER "Enables SSE 4.2 optimizations.")
detect_var(HAVE_SSSE3 0 NUMBER "Enables SSSE3 optimizations.")

# Flags describing the build environment.
detect_var(HAVE_FEXCEPT 0 NUMBER
                   "Internal flag, GNU fenv.h present for target.")
detect_var(HAVE_PTHREAD_H 0 NUMBER
                   "Internal flag, target pthread support.")
detect_var(HAVE_UNISTD_H 0 NUMBER
                   "Internal flag, unistd.h present for target.")
detect_var(HAVE_WXWIDGETS 0 NUMBER "WxWidgets present.")

# Variables in this section can be set from the CMake command line or
# from within the CMake GUI. The variables control project features.

# Build configuration flags.
config_var(CONFIG_BIG_ENDIAN 0 NUMBER "Internal flag.")
config_var(CONFIG_GCC 0 NUMBER "Building with GCC (detect).")
config_var(CONFIG_GCOV 0 NUMBER "Enable gcov support.")
config_var(CONFIG_GPROF 0 NUMBER "Enable gprof support.")

config_var(CONFIG_MULTITHREAD 1 NUMBER "Multithread support.")
config_var(CONFIG_OS_SUPPORT 0 NUMBER "Internal flag.")
config_var(CONFIG_PIC 0 NUMBER "Build with PIC enabled.")
config_var(CONFIG_RUNTIME_CPU_DETECT 1 NUMBER
                   "Runtime CPU detection support.")
config_var(CONFIG_SHARED 0 NUMBER "Build shared libs.")
config_var(CONFIG_STATIC 1 NUMBER "Build static libs.")

# Debugging flags.
config_var(CONFIG_DEBUG 0 NUMBER "Debug build flag.")

#
# Variables in this section control optional features of the build system.
#
option_var(ENABLE_CCACHE "Enable ccache support." OFF)
option_var(ENABLE_DECODE_PERF_TESTS "Enables decoder performance tests"
                   OFF)
option_var(ENABLE_DISTCC "Enable distcc support." OFF)
option_var(ENABLE_DOCS
                   "Enable documentation generation (doxygen required)." ON)
option_var(ENABLE_ENCODE_PERF_TESTS "Enables encoder performance tests"
                   OFF)
option_var(ENABLE_EXAMPLES "Enables build of example code." ON)
option_var(ENABLE_GOMA "Enable goma support." OFF)
option_var(ENABLE_IDE_TEST_HOSTING "Enables running tests within IDEs like MSVS and Xcode." OFF)
option_var(ENABLE_NASM "Use nasm instead of yasm for x86 assembly." OFF)
option_var(ENABLE_TESTDATA "Enables unit test data download targets."
                   ON)
option_var(ENABLE_TESTS "Enables unit tests." ON)
option_var(ENABLE_TOOLS "Enable applications in tools sub directory."
                   ON)
option_var(ENABLE_WERROR "Converts warnings to errors at compile time."
                   OFF)

# ARM assembly/intrinsics flags.
option_var(ENABLE_NEON "Enables NEON optimizations on ARM targets." ON)

# MIPS assembly/intrinsics flags.
option_var(ENABLE_DSPR2 "Enables DSPR2 optimizations on MIPS targets."
                   OFF)
option_var(ENABLE_MSA "Enables MSA optimizations on MIPS targets." OFF)

# VSX intrinsics flags.
option_var(ENABLE_VSX "Enables VSX optimizations on PowerPC targets."
                   ON)

# x86/x86_64 assembly/intrinsics flags.
option_var(ENABLE_MMX
                   "Enables MMX optimizations on x86/x86_64 targets." ON)
option_var(ENABLE_SSE
                   "Enables SSE optimizations on x86/x86_64 targets." ON)
option_var(ENABLE_SSE2
                   "Enables SSE2 optimizations on x86/x86_64 targets." ON)
option_var(ENABLE_SSE3
                   "Enables SSE3 optimizations on x86/x86_64 targets." ON)
option_var(ENABLE_SSSE3
                   "Enables SSSE3 optimizations on x86/x86_64 targets." ON)
option_var(ENABLE_SSE4_1
                   "Enables SSE4_1 optimizations on x86/x86_64 targets." ON)
option_var(ENABLE_SSE4_2
                   "Enables SSE4_2 optimizations on x86/x86_64 targets." ON)
option_var(ENABLE_AVX
                   "Enables AVX optimizations on x86/x86_64 targets." ON)
option_var(ENABLE_AVX2
                   "Enables AVX2 optimizations on x86/x86_64 targets." ON)
