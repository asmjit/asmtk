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
using asmjit::Operand_;
using asmjit::X86Assembler;

// ============================================================================
// [asmtk::AsmParser]
// ============================================================================

//! Asm parser.
class AsmParser {
public:
  AsmParser(X86Assembler* assembler);
  ~AsmParser();

  Error parse(const char* input, size_t len);
  inline Error parse(const char* input) { return parse(input, asmjit::kInvalidIndex); }

private:
  Error _parseOp(Operand_& op, AsmToken* termToken);

  X86Assembler* _assembler;
  AsmTokenizer _tokenizer;
};

} // asmtk namespace

// [Guard]
#endif // ASMTK_ASMPARSER_H
