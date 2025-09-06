// [AsmTk]
// Assembler toolkit based on AsmJit.
//
// [License]
// Zlib - See LICENSE.md file in the package.

#define ASMTK_EXPORTS

#include "./asmtokenizer.h"

namespace asmtk {

// ============================================================================
// [asmtk::CharKind / CharMap]
// ============================================================================

//! Flags used during tokenization.
enum StateFlags : uint32_t {
  //! Parsed '.' prefix.
  kStateDotPrefix = 0x10000000u,
  //! Parsed '$' prefix.
  kStateDollarPrefix = 0x20000000u,
  //! Parsed number prefix [0b|0x].
  kStateNumberPrefix = 0x40000000u,
  //! Parsed number suffix [b|o|q|h].
  kStateNumberSuffix = 0x80000000u
};

enum CharKind : uint32_t {
  // Digit [0-9], HEX [A-F] and the remaining ASCII [G-Z].
  kChar0x0, kChar0x1, kChar0x2, kChar0x3, kChar0x4, kChar0x5, kChar0x6, kChar0x7,
  kChar0x8, kChar0x9, kChar0xA, kChar0xB, kChar0xC, kChar0xD, kChar0xE, kChar0xF,
  kCharAxG, kCharAxH, kCharAxI, kCharAxJ, kCharAxK, kCharAxL, kCharAxM, kCharAxN,
  kCharAxO, kCharAxP, kCharAxQ, kCharAxR, kCharAxS, kCharAxT, kCharAxU, kCharAxV,
  kCharAxW, kCharAxX, kCharAxY, kCharAxZ,

  kCharUnd, // Underscore
  kCharDot, // Dot
  kCharSym, // Special characters that can be considered a symbol [$@_].
  kCharUsd, // Dollar sign.
  kCharDsh, // Dash.
  kCharPcn, // Punctuation.
  kCharSpc, // Space.
  kCharExt, // Extended ASCII character (0x80 and above), acts as non-recognized.
  kCharInv  // Invalid (non-recognized) character.
};

#define C(ID) uint8_t(kChar##ID)
static const uint8_t CharMap[] = {
  C(Inv), C(Inv), C(Inv), C(Inv), C(Inv), C(Inv), C(Inv), C(Inv), // 000-007 ........ | All invalid.
  C(Inv), C(Spc), C(Spc), C(Spc), C(Spc), C(Spc), C(Inv), C(Inv), // 008-015 .     .. | Spaces 0x9-0xD.
  C(Inv), C(Inv), C(Inv), C(Inv), C(Inv), C(Inv), C(Inv), C(Inv), // 016-023 ........ | All invalid.
  C(Inv), C(Inv), C(Inv), C(Inv), C(Inv), C(Inv), C(Inv), C(Inv), // 024-031 ........ | All invalid.
  C(Spc), C(Pcn), C(Pcn), C(Pcn), C(Usd), C(Pcn), C(Pcn), C(Pcn), // 032-039  !"#$%&' |
  C(Pcn), C(Pcn), C(Pcn), C(Pcn), C(Pcn), C(Dsh), C(Dot), C(Pcn), // 040-047 ()*+,-./ |
  C(0x0), C(0x1), C(0x2), C(0x3), C(0x4), C(0x5), C(0x6), C(0x7), // 048-055 01234567 |
  C(0x8), C(0x9), C(Pcn), C(Pcn), C(Pcn), C(Pcn), C(Pcn), C(Pcn), // 056-063 89:;<=>? |
  C(Sym), C(0xA), C(0xB), C(0xC), C(0xD), C(0xE), C(0xF), C(AxG), // 064-071 @ABCDEFG |
  C(AxH), C(AxI), C(AxJ), C(AxK), C(AxL), C(AxM), C(AxN), C(AxO), // 072-079 HIJKLMNO |
  C(AxP), C(AxQ), C(AxR), C(AxS), C(AxT), C(AxU), C(AxV), C(AxW), // 080-087 PQRSTUVW |
  C(AxX), C(AxY), C(AxZ), C(Pcn), C(Pcn), C(Pcn), C(Pcn), C(Und), // 088-095 XYZ[\]^_ |
  C(Pcn), C(0xA), C(0xB), C(0xC), C(0xD), C(0xE), C(0xF), C(AxG), // 096-103 `abcdefg |
  C(AxH), C(AxI), C(AxJ), C(AxK), C(AxL), C(AxM), C(AxN), C(AxO), // 104-111 hijklmno |
  C(AxP), C(AxQ), C(AxR), C(AxS), C(AxT), C(AxU), C(AxV), C(AxW), // 112-119 pqrstuvw |
  C(AxX), C(AxY), C(AxZ), C(Pcn), C(Pcn), C(Pcn), C(Pcn), C(Inv), // 120-127 xyz{|}~  |
  C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), // 128-135 ........ | Extended.
  C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), // 136-143 ........ |
  C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), // 144-151 ........ |
  C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), // 152-159 ........ |
  C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), // 160-167 ........ |
  C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), // 168-175 ........ |
  C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), // 176-183 ........ |
  C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), // 184-191 ........ |
  C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), // 192-199 ........ |
  C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), // 200-207 ........ |
  C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), // 208-215 ........ |
  C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), // 216-223 ........ |
  C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), // 224-231 ........ |
  C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), // 232-239 ........ |
  C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), // 240-247 ........ |
  C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext), C(Ext)  // 248-255 ........ |
};
#undef C

// ============================================================================
// [asmtk::AsmTokenizer]
// ============================================================================

AsmTokenizer::AsmTokenizer() noexcept
  : _input(nullptr),
    _end(nullptr),
    _cur(nullptr),
    _stodctx() {}

AsmTokenizer::~AsmTokenizer() noexcept {}

AsmTokenType AsmTokenizer::next(AsmToken* token, ParseFlags parse_flags) noexcept {
  const uint8_t* cur = _cur;
  const uint8_t* end = _end;

  // Skip spaces.
  const uint8_t* start = cur;
  if (cur == end)
    return token->set_data(AsmTokenType::kEnd, start, cur);

  uint32_t c = cur[0];
  uint32_t m = CharMap[c];
  uint32_t state_flags = 0;
  bool is_comment = false;

  // Skip Whitespaces
  // ----------------

  if (m == kCharSpc) {
    do {
      cur++;
      if (c == '\n')
        goto NL;

      if (cur == end)
        goto End;

      c = cur[0];
      m = CharMap[c];
    } while (m == kCharSpc);
  }

  // Skip Comment
  // ------------

  if (c == ';')
    is_comment = true;

  if (c == '/' && size_t(end - cur) >= 2 && cur[1] == '/')
    is_comment = true;

  if (is_comment) {
    for (;;) {
      if (++cur == end)
        goto End;
      c = cur[0];
      if (c == '\n')
        goto NL;
    }
  }

  // The beginning of the token.
  start = cur;

  // Parse Prefixes
  // --------------

  if (c == '$') {
    if (++cur == end) {
      _cur = cur;
      return token->set_data(AsmTokenType::kSym, start, cur);
    }

    state_flags |= kStateDollarPrefix;
    c = cur[0];
    m = CharMap[c];
  }
  else if (c == '.') {
    if (++cur == end) {
      _cur = cur;
      return token->set_data(AsmTokenType::kInvalid, start, cur);
    }

    state_flags |= kStateDotPrefix;
    c = cur[0];
    m = CharMap[c];
  }

  // Parse Number
  // ------------

  // Only parse numbers if we are not forced to always parse numbers as symbols.
  if (!asmjit::Support::test(parse_flags, ParseFlags::kParseSymbol) && (state_flags & kStateDotPrefix) == 0) {
    // The number either starts with [0..9], which could contain an optional
    // [0x|0b] prefixes, or $[0-9], which is a hexadecimal prefix as well.
    if (m <= kChar0x9) {
      uint64_t val = m;
      uint32_t base = 10;
      uint32_t shift = 0;

      if (++cur == end) {
        _cur = cur;
        token->_u64 = val;
        return token->set_data(AsmTokenType::kU64, start, cur);
      }

      // Parse a binary or hexadecimal number prefixed by [$|0x|0b].
      c = cur[0];
      m = CharMap[c];

      if (val == 0 || (state_flags & kStateDollarPrefix) != 0) {
        if (state_flags & kStateDollarPrefix) {
          // Hexadecimal number.
          base = 16;
          shift = 4;
          state_flags |= kStateNumberPrefix;
        }
        else {
          // Parse 'b' or 'x'.
          if (m == kChar0xB || m == kCharAxX) {
            base = 16;
            shift = 4;
            state_flags |= kStateNumberPrefix;

            if (m == kChar0xB) {
              base = 2;
              shift = 1;
            }

            // There must be at least one valid digit.
            if (++cur == end)
              goto Invalid;

            c = cur[0];
            m = CharMap[c];
          }
          else {
            // Octal number if there is no prefix.
            base = 8;
            shift = 3;
            goto ParseDigits;
          }

          if (m >= base)
            goto Invalid;
        }

        while (m < base) {
          val = (val << shift) | m;
          if (++cur == end) break;

          c = cur[0];
          m = CharMap[c];
        }

        if (cur != end && m <= kCharUnd)
          goto Invalid;

        _cur = cur;
        token->_u64 = val;
        return token->set_data(AsmTokenType::kU64, start, cur);
      }

      // Parse a decimal number or prepare for parsing a binary/octal/hexadecimal
      // number if a suffix follows. Since we parse suffix at the end we perform
      // decimal parsing now.
ParseDigits:
      {
        uint32_t highest_digit = uint32_t(val);

        for (;;) {
          c -= uint32_t('0');
          if (c < 10) {
            val = val * 10 + c;
            highest_digit = std::max<uint32_t>(highest_digit, c);

            if (++cur == end)
              break;
            c = cur[0];
            continue;
          }
          m = CharMap[c + uint32_t('0')];

          if (m <= kChar0xF) {
            // Parse an optional 'b' suffix (otherwise it's a hexadecimal number).
            if (m == 0xB && highest_digit <= 1) {
              if (++cur != end) {
                c = cur[0];
                m = CharMap[c];
                if (m <= kChar0xF)
                  goto ParseHex;
              }

              base = 2;
              shift = 1;
              state_flags |= kStateNumberSuffix;
            }
            else {
ParseHex:
              highest_digit = 0xF;

              while (++cur != end) {
                c = cur[0];
                m = CharMap[c];
                if (m > kChar0xF)
                  break;
              }
            }
          }
          break;
        }

        if (cur != end && m <= kCharUnd) {
          // Parse optional [h|o|q] suffixes.
          if (m == kCharAxH) {
            base = 16;
            shift = 4;

            cur++;
            state_flags |= kStateNumberSuffix;
          }
          else if (m == kCharAxO || m == kCharAxQ) {
            base = 8;
            shift = 3;

            cur++;
            state_flags |= kStateNumberSuffix;
          }
          else {
            goto Invalid;
          }

          if (cur != end) {
            c = cur[0];
            m = CharMap[c];

            if (m <= kCharUnd)
              goto Invalid;
          }
        }

        if (highest_digit >= base)
          goto Invalid;

        if (base != 10) {
          const uint8_t* alt_cur = start;
          const uint8_t* alt_end = cur - ((state_flags & kStateNumberSuffix) != 0);

          val = 0;
          while (alt_cur != alt_end) {
            val <<= shift;
            val += CharMap[*alt_cur++];
          }
        }
      }

      _cur = cur;
      token->_u64 = val;
      return token->set_data(AsmTokenType::kU64, start, cur);
    }
  }

  // Parse Symbol
  // ------------

  // Parse '??xxx' as used by Windows ABI for mangled C++ symbols.
  if (c == '?' && (size_t)(end - cur) > 2 && cur[1] == '?' && CharMap[cur[2]] <= kCharUsd) {
    m = kCharUsd;
    cur += 2;
  }

  if (m <= kCharUsd) {
    uint32_t mSymMax = asmjit::Support::test(parse_flags, ParseFlags::kIncludeDashes) ? kCharDsh : kCharUsd;

    while (++cur != end) {
      c = cur[0];
      m = CharMap[c];

      if (m <= mSymMax)
        continue;

      break;
    }

    _cur = cur;
    return token->set_data(AsmTokenType::kSym, start, cur);
  }

  // Parse Punctuation
  // -----------------

  if (m <= kCharPcn) {
    AsmTokenType type = AsmTokenType::kOther;
    switch (c) {
      case '{': type = AsmTokenType::kLCurl   ; break;
      case '}': type = AsmTokenType::kRCurl   ; break;
      case '[': type = AsmTokenType::kLBracket; break;
      case ']': type = AsmTokenType::kRBracket; break;
      case '(': type = AsmTokenType::kLParen  ; break;
      case ')': type = AsmTokenType::kRParen  ; break;
      case '+': type = AsmTokenType::kAdd     ; break;
      case '-': type = AsmTokenType::kSub     ; break;
      case '*': type = AsmTokenType::kMul     ; break;
      case '/': type = AsmTokenType::kDiv     ; break;
      case ',': type = AsmTokenType::kComma   ; break;
      case ':': type = AsmTokenType::kColon   ; break;
    }
    _cur = ++cur;
    return token->set_data(type, start, cur);
  }

Invalid:
  _cur = cur;
  return token->set_data(AsmTokenType::kInvalid, start, cur);

NL:
  _cur = cur;
  return token->set_data(AsmTokenType::kNL, start, cur);

End:
  _cur = cur;
  return token->set_data(AsmTokenType::kEnd, start, cur);
}

} // {asmtk}
