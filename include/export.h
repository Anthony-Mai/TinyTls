#ifndef EXPORT_TAG_INCLUDED
#define EXPORT_TAG_INCLUDED

#if defined(_WIN32) || defined(__CYGWIN__) || defined(MSVC)
  #ifdef BUILDING_DLL
    #ifdef __GNUC__
      #define EXPORT __attribute__((dllexport))
    #else
      #define EXPORT __declspec(dllexport) // Note: actually gcc seems to also supports this syntax.
    #endif
  #else
    #ifdef __GNUC__
      #define EXPORT __attribute__((dllimport))
    #else
      #define EXPORT __declspec(dllimport) // Note: actually gcc seems to also supports this syntax.
    #endif
  #endif
  #define DLL_LOCAL
#else
  #if __GNUC__ >= 4
    #define EXPORT __attribute__((visibility ("default")))
    #define DLL_LOCAL  __attribute__((visibility ("hidden")))
  #else
    #define EXPORT
    #define DLL_LOCAL
  #endif
#endif

#endif //EXPORT_TAG_INCLUDED
