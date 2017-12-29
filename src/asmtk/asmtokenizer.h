// [AsmTk]
// Assembler toolkit based on AsmJit.
//
// [License]
// Zlib - See LICENSE.md file in the package.

// [Guard]
#ifndef _ASMTK_ASMTOKENIZER_H
#define _ASMTK_ASMTOKENIZER_H

// [Dependencies]
#include "./globals.h"
#include "./strtod.h"

namespace asmtk {

// ============================================================================
// [asmtk::AsmToken]
// ============================================================================

struct AsmToken {
  enum Type : uint32_t {
    kEnd,
    kNL,
    kSym,
    kNSym,
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

  inline bool is(char c0) {
    return size == 1 && data[0] == c0;
  }
  inline bool is(char c0, char c1) {
    return size == 2 && data[0] == c0 && data[1] == c1;
  }
  inline bool is(char c0, char c1, char c2) {
    return size == 3 && data[0] == c0 && data[1] == c1 && data[2] == c2;
  }
  inline bool is(char c0, char c1, char c2, char c3) {
    return size == 4 && data[0] == c0 && data[1] == c1 && data[2] == c2 && data[3] == c3;
  }
  inline bool is(char c0, char c1, char c2, char c3, char c4) {
    return size == 5 && data[0] == c0 && data[1] == c1 && data[2] == c2 && data[3] == c3 && data[4] == c4;
  }

  inline void reset() {
    type = kEnd;
    data = nullptr;
    size = 0;
    u64 = 0;
  }

  inline uint32_t setData(uint32_t type, const uint8_t* data, size_t size) {
    this->data = data;
    this->size = size;
    this->type = type;
    return type;
  }

  inline uint32_t setData(uint32_t type, const uint8_t* data, const uint8_t* end) {
    return setData(type, data, (size_t)(end - data));
  }

  uint32_t type;
  const uint8_t* data;
  size_t size;

  union {
    double f64;
    int64_t i64;
    uint64_t u64;
    uint8_t valueBytes[8];
  };
};

// ============================================================================
// [asmtk::AsmTokenizer]
// ============================================================================

class AsmTokenizer {
public:
  //! Tokenizer options.
  enum ParseFlags : uint32_t {
    kParseSymbol          = 0x00000001U, //!< Don't attempt to parse number (always parse symbol).
    kParseDashes          = 0x00000002U  //!< Consider dashes as text in a parsed symbol.
  };

  //! Flags used during tokenization (cannot be used as options).
  enum StateFlags : uint32_t {
    kStateDotPrefix       = 0x10000000U, //!< Parsed '.' prefix.
    kStateDollarPrefix    = 0x20000000U, //!< Parsed '$' prefix.
    kStateNumberPrefix    = 0x40000000U, //!< Parsed number prefix [0b|0x].
    kStateNumberSuffix    = 0x80000000U  //!< Parsed number suffix [b|o|q|h].
  };

  AsmTokenizer();
  uint32_t next(AsmToken* token, uint32_t flags = 0);
  inline void putBack(AsmToken* token) { _cur = token->data; }

  inline void setInput(const uint8_t* input, size_t size) {
    _input = input;
    _end = input + size;
    _cur = input;
  }

  const uint8_t* _input;
  const uint8_t* _end;
  const uint8_t* _cur;

  StrToD _stodctx;
};

} // asmtk namespace

// [Guard]
#endif // _ASMTK_ASMTOKENIZER_H
