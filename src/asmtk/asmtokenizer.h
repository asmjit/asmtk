// [AsmTk]
// Assembler toolkit based on AsmJit.
//
// [License]
// Zlib - See LICENSE.md file in the package.

// [Guard]
#ifndef ASMTK_ASMTOKENIZER_H
#define ASMTK_ASMTOKENIZER_H

// [Dependencies]
#include "./strtod.h"
#include <asmjit/base.h>

namespace asmtk {

struct AsmToken {
  enum Type {
    kEnd,
    kNL,
    kSym,
    kU64,
    kF64,
    kLCurl,
    kRCurl,
    kLBracket,
    kRBracket,
    kLParen,
    kRParen,
    kAdd,
    kSub,
    kMul,
    kDiv,
    kComma,
    kColon,
    kOther,
    kInvalid
  };

  inline uint32_t setData(uint32_t type, const uint8_t* data, size_t len) {
    //printf("TOKEN: %.*s\n", (int)len, data);
    this->data = data;
    this->len = len;
    this->type = type;
    return type;
  }

  inline uint32_t setData(uint32_t type, const uint8_t* data, const uint8_t* end) {
    return setData(type, data, (size_t)(end - data));
  }

  uint32_t type;
  const uint8_t* data;
  size_t len;

  union {
    double f64;
    int64_t i64;
    uint64_t u64;
  };
};

class AsmTokenizer {
public:
  AsmTokenizer();
  uint32_t next(AsmToken* token);
  inline void back(AsmToken* token) { _cur = token->data; }

  inline void setInput(const uint8_t* input, size_t len) {
    _input = input;
    _end = input + len;
    _cur = input;
  }

  const uint8_t* _input;
  const uint8_t* _end;
  const uint8_t* _cur;

  StrToD _stodctx;
};

} // asmtk namespace

// [Guard]
#endif // ASMTK_ASMTOKENIZER_H
