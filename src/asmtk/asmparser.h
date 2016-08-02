// [AsmTk]
// Assembler toolkit based on AsmJit.
//
// [License]
// Zlib - See LICENSE.md file in the package.

// [Guard]
#ifndef ASMTK_ASMPARSER_H
#define ASMTK_ASMPARSER_H

// [Dependencies]
#include "./strtod.h"
#include "./asmtokenizer.h"
#include <asmjit/x86.h>

namespace asmtk {

using asmjit::Error;

// ============================================================================
// [asmtk::AsmParser]
// ============================================================================

//! Asm parser.
class AsmParser {
public:
  AsmParser(asmjit::CodeEmitter* emitter);
  ~AsmParser();

  Error parse(const char* input, size_t len);
  inline Error parse(const char* input) { return parse(input, asmjit::kInvalidIndex); }

private:
  asmjit::CodeEmitter* _emitter;
  AsmTokenizer _tokenizer;
};

} // asmtk namespace

// [Guard]
#endif // ASMTK_ASMPARSER_H
