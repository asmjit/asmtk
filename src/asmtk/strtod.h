// [AsmTk]
// Assembler toolkit based on AsmJit.
//
// [License]
// Zlib - See LICENSE.md file in the package.

// [Guard]
#ifndef _ASMTK_STRTOD_H
#define _ASMTK_STRTOD_H

// [Dependencies]
#include "./globals.h"

#if defined(_WIN32) || defined(_WINDOWS)
  #define ASMTK_STRTOD_MSLOCALE
  #include <locale.h>
  #include <stdlib.h>
#else
  #define ASMTK_STRTOD_XLOCALE
  #include <locale.h>
  #include <stdlib.h>
  #if ASMJIT_OS_BSD || ASMJIT_OS_MAC
    // xlocale.h is not available on Linux anymore, it uses <locale.h>.
    #include <xlocale.h>
  #endif
#endif

namespace asmtk {

// ============================================================================
// [asmtk::StrToD]
// ============================================================================

class StrToD {
public:
#if defined(ASMTK_STRTOD_MSLOCALE)
  inline StrToD() { handle = _create_locale(LC_ALL, "C"); }
  inline ~StrToD() { _free_locale(handle); }

  inline bool isOk() const { return handle != NULL; }
  inline double conv(const char* s, char** end) const { return _strtod_l(s, end, handle); }

  _locale_t handle;
#elif defined(ASMTK_STRTOD_XLOCALE)
  inline StrToD() { handle = newlocale(LC_ALL_MASK, "C", NULL); }
  inline ~StrToD() { freelocale(handle); }

  inline bool isOk() const { return handle != NULL; }
  inline double conv(const char* s, char** end) const { return strtod_l(s, end, handle); }

  locale_t handle;
#else
  // Time bomb!
  inline bool isOk() const { return true; }
  inline double conv(const char* s, char** end) const { return strtod(s, end); }
#endif
};

} // asmtk namespace

// [Guard]
#endif // _ASMTK_STRTOD_H
