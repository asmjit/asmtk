// [AsmTk]
// Assembler toolkit based on AsmJit.
//
// [License]
// Zlib - See LICENSE.md file in the package.

// [Dependencies]
#include "./asmparser.h"
#include "./parserutils.h"

namespace asmtk {

using namespace asmjit;

// ============================================================================
// [asmtk::X86AsmLimits]
// ============================================================================

enum X86AsmLimits : uint32_t {
  kX86MinRegLen = 2,
  kX86MaxRegLen = 5,

  kX86MinSizeLen = 4,
  kX86MaxSizeLen = 7
};

// ============================================================================
// [asmtk::X86Directive]
// ============================================================================

enum X86Directive : uint32_t {
  kX86DirectiveNone  = 0,
  kX86DirectiveAlign,
  kX86DirectiveDB,
  kX86DirectiveDW,
  kX86DirectiveDD,
  kX86DirectiveDQ
};

// ============================================================================
// [asmtk::X86Alias]
// ============================================================================

enum X86Alias : uint32_t {
  kX86AliasStart = 0x00010000U,

  kX86AliasMovabs = kX86AliasStart,

  kX86AliasInsb,
  kX86AliasInsd,
  kX86AliasInsw,

  kX86AliasOutsb,
  kX86AliasOutsd,
  kX86AliasOutsw,

  kX86AliasCmpsb,
  kX86AliasCmpsd,
  kX86AliasCmpsq,
  kX86AliasCmpsw,

  kX86AliasMovsb,
  kX86AliasMovsd,
  kX86AliasMovsq,
  kX86AliasMovsw,

  kX86AliasLodsb,
  kX86AliasLodsd,
  kX86AliasLodsq,
  kX86AliasLodsw,

  kX86AliasScasb,
  kX86AliasScasd,
  kX86AliasScasq,
  kX86AliasScasw,

  kX86AliasStosb,
  kX86AliasStosd,
  kX86AliasStosq,
  kX86AliasStosw
};

// ============================================================================
// [asmtk::AsmParser]
// ============================================================================

AsmParser::AsmParser(CodeEmitter* emitter) noexcept
  : _emitter(emitter),
    _currentCommandOffset(0),
    _unknownSymbolHandler(NULL),
    _unknownSymbolHandlerData(NULL) {}
AsmParser::~AsmParser() noexcept {}

// ============================================================================
// [asmtk::AsmParser - Input]
// ============================================================================

uint32_t AsmParser::nextToken(AsmToken* token, uint32_t flags) noexcept {
  return _tokenizer.next(token, flags);
}

void AsmParser::putTokenBack(AsmToken* token) noexcept {
  _tokenizer.putBack(token);
}

// ============================================================================
// [asmtk::AsmParser - Parse]
// ============================================================================

static void strToLower(uint8_t* dst, const uint8_t* src, size_t len) noexcept{
  for (size_t i = 0; i < len; i++)
    dst[i] = StringUtils::toLower<uint8_t>(uint8_t(src[i]));
}

#define COMB_CHAR_2(a, b) \
  ((uint32_t(a) << 8) | uint32_t(b))

#define COMB_CHAR_4(a, b, c, d) \
  ((uint32_t(a) << 24) | (uint32_t(b) << 16) | (uint32_t(c) << 8) | uint32_t(d))

static bool x86ParseRegister(Operand_& op, const uint8_t* s, size_t len) noexcept {
  if (len < kX86MinRegLen || len > kX86MaxRegLen) return false;
  const uint8_t* sEnd = s + len;

  uint32_t c0 = StringUtils::toLower<uint32_t>(s[0]);
  uint32_t c1 = StringUtils::toLower<uint32_t>(s[1]);
  uint32_t c2 = len > 2 ? StringUtils::toLower<uint32_t>(s[2]) : uint32_t(0);
  uint32_t cn = (c0 << 8) + c1;

  uint32_t rType = X86Reg::kRegNone;
  uint32_t rId = 0;

  static const uint8_t abcdTo0312[] = { 0, 3, 1, 2 };

  // [AL|BL|CL|DL]
  // [AH|BH|CH|DH]
  // [AX|BX|CX|DX]
  // [ES|CS|SS|DS|FS|GS]
  if (len == 2) {
    if (c0 >= 'a' && c0 <= 'd') {
      rId = abcdTo0312[c0 - 'a'];
      if (c1 == 'l') { rType = X86Reg::kRegGpbLo; goto Done; }
      if (c1 == 'h') { rType = X86Reg::kRegGpbHi; goto Done; }
      if (c1 == 'x') { rType = X86Reg::kRegGpw  ; goto Done; }
    }

    if (c1 == 's') {
      rType = X86Reg::kRegSeg;
      if (c0 == 'e') { rId = X86Seg::kIdEs; goto Done; }
      if (c0 == 'c') { rId = X86Seg::kIdCs; goto Done; }
      if (c0 == 's') { rId = X86Seg::kIdSs; goto Done; }
      if (c0 == 'd') { rId = X86Seg::kIdDs; goto Done; }
      if (c0 == 'f') { rId = X86Seg::kIdFs; goto Done; }
      if (c0 == 'g') { rId = X86Seg::kIdGs; goto Done; }
    }

    rType = X86Reg::kRegGpw;
    goto TrySpBpSiDi;
  }

  // [SP|BP|SI|DI]
  // [SPL|BPL|SIL|DIL]
  // [EAX|EBX|ECX|EDX|ESP|EBP|EDI|ESI]
  // [RAX|RBX|RCX|RDX|RSP|RBP|RDI|RSI]
  // [RIP]
  if (len == 3) {
    if (c2 == 'l') {
      rType = X86Reg::kRegGpbLo;
      goto TrySpBpSiDi;
    }

    if (c0 == 'e' || c0 == 'r') {
      cn = (c1 << 8) | c2;

      if (c0 == 'r' && cn == COMB_CHAR_2('i', 'p')) {
        rType = X86Reg::kRegRip;
        goto Done;
      }

      rType = (c0 == 'e') ? X86Reg::kRegGpd : X86Reg::kRegGpq;
      if (cn == COMB_CHAR_2('a', 'x')) { rId = X86Gp::kIdAx; goto Done; }
      if (cn == COMB_CHAR_2('d', 'x')) { rId = X86Gp::kIdDx; goto Done; }
      if (cn == COMB_CHAR_2('b', 'x')) { rId = X86Gp::kIdBx; goto Done; }
      if (cn == COMB_CHAR_2('c', 'x')) { rId = X86Gp::kIdCx; goto Done; }

TrySpBpSiDi:
      if (cn == COMB_CHAR_2('s', 'p')) { rId = X86Gp::kIdSp; goto Done; }
      if (cn == COMB_CHAR_2('b', 'p')) { rId = X86Gp::kIdBp; goto Done; }
      if (cn == COMB_CHAR_2('s', 'i')) { rId = X86Gp::kIdSi; goto Done; }
      if (cn == COMB_CHAR_2('d', 'i')) { rId = X86Gp::kIdDi; goto Done; }
    }
  }

  // [R?|R?B|R?W|R?D]
  if (c0 == 'r') {
    s++;
    rType = X86Reg::kRegGpq;

    // Handle 'b', 'w', and 'd' suffixes.
    c2 = StringUtils::toLower<uint32_t>(sEnd[-1]);
    if (c2 == 'b')
      rType = X86Reg::kRegGpbLo;
    else if (c2 == 'w')
      rType = X86Reg::kRegGpw;
    else if (c2 == 'd')
      rType = X86Reg::kRegGpd;
    sEnd -= (rType != X86Reg::kRegGpq);
  }
  // [XMM?|YMM?|ZMM?]
  else if (c0 >= 'x' && c0 <= 'z' && c1 == 'm' && c2 == 'm') {
    s += 3;
    rType = X86Reg::kRegXmm + (c0 - 'x');
  }
  // [K?]
  else if (c0 == 'k') {
    s++;
    rType = X86Reg::kRegK;
  }
  // [ST?|FP?]
  else if ((c0 == 's' && c1 == 't') | (c0 == 'f' && c1 == 'p')) {
    s += 2;
    rType = X86Reg::kRegFp;
  }
  // [MM?]
  else if (c0 == 'm' && c1 == 'm') {
    s += 2;
    rType = X86Reg::kRegMm;
  }
  // [BND?]
  else if (c0 == 'b' && c1 == 'n' && c2 == 'd') {
    s += 3;
    rType = X86Reg::kRegBnd;
  }
  // [CR?]
  else if (c0 == 'c' && c1 == 'r') {
    s += 2;
    rType = X86Reg::kRegCr;
  }
  // [DR?]
  else if (c0 == 'd' && c1 == 'r') {
    s += 2;
    rType = X86Reg::kRegDr;
  }
  else {
    return false;
  }

  // Parse the register index.
  rId = uint32_t(s[0]) - '0';
  if (rId >= 10) return false;

  if (++s < sEnd) {
    c0 = uint32_t(*s++) - '0';
    if (c0 >= 10) return false;
    rId = rId * 10 + c0;

    // Maximum register
    if (rId >= 32) return false;
  }

  // Fail if the whole input wasn't parsed.
  if (s != sEnd) return false;

  // Fail if the register index is greater than allowed.
  if (rId >= x86OpData.archRegs.regCount[rType]) return false;

Done:
  op._initReg(x86OpData.archRegs.regInfo[rType].getSignature(), rId);
  return true;
}

static uint32_t x86ParseSize(const uint8_t* s, size_t len) noexcept {
  constexpr uint32_t kX86MinSizeLen = 4;
  constexpr uint32_t kX86MaxSizeLen = 7;

  if (len < kX86MinSizeLen || len > kX86MaxSizeLen)
    return 0;

  // Start from the end.
  ParserUtils::WordParser suffix;
  suffix.addLowercasedChar(s + len - 4, 0);
  suffix.addLowercasedChar(s + len - 4, 1);
  suffix.addLowercasedChar(s + len - 4, 2);
  suffix.addLowercasedChar(s + len - 4, 3);

  if (suffix.test('w', 'o', 'r', 'd')) {
    // Parsed 'word'.
    if (len == 4) return 2;

    // Sizes of length '5':
    ParserUtils::WordParser wordSize;
    wordSize.addLowercasedChar(s, 0);

    if (len == 5) {
      // Check the most common first.
      if (wordSize.test('d')) return 4;
      if (wordSize.test('q')) return 8;
      if (wordSize.test('o')) return 16;
      if (wordSize.test('x')) return 16;
      if (wordSize.test('y')) return 32;
      if (wordSize.test('z')) return 64;

      // `fword` (aka far word, 16:32 m48 pointer) and `tword` (m80).
      if (wordSize.test('f')) return 6;
      if (wordSize.test('t')) return 10;
    }

    // Sizes of length '6':
    wordSize.addLowercasedChar(s, 1);
    if (len == 6) {
      if (wordSize.test('m', 'm')) return 8;
      if (wordSize.test('d', 'q')) return 16;
      if (wordSize.test('q', 'q')) return 32;
    }

    // Sizes of length '7':
    wordSize.addLowercasedChar(s, 2);
    if (len == 7) {
      if (wordSize.test('x', 'm', 'm')) return 16;
      if (wordSize.test('y', 'm', 'm')) return 32;
      if (wordSize.test('z', 'm', 'm')) return 64;
    }
  }

  // Parsed 'byte'.
  if (suffix.test('b', 'y', 't', 'e'))
    return len == 4 ? 1 : 0;

  return 0;
}

static Error asmHandleSymbol(AsmParser& parser, Operand_& dst, const uint8_t* name, size_t len) noexcept {
  Label L = parser._emitter->getLabelByName(reinterpret_cast<const char*>(name), len);

  if (!L.isValid()) {
    if (parser.hasUnknownSymbolHandler()) {
      Error err = parser._unknownSymbolHandler(&parser, static_cast<Operand*>(&dst), reinterpret_cast<const char*>(name), len);
      if (err)
        return err;

      if (!dst.isNone())
        return kErrorOk;
    }

    L = parser._emitter->newNamedLabel(reinterpret_cast<const char*>(name), len);
    if (!L.isValid()) return DebugUtils::errored(kErrorNoHeapMemory);
  }

  dst = L;
  return kErrorOk;
}

static Error x86ParseOperand(AsmParser& parser, Operand_& dst, AsmToken* token) noexcept {
  uint32_t type = token->type;
  uint32_t memSize = 0;
  Operand seg;

  // Symbol, could be register, memory operand size, or label.
  if (type == AsmToken::kSym) {
    // Try register.
    if (x86ParseRegister(dst, token->data, token->len)) {
      if (!dst.as<X86Reg>().isSeg())
        return kErrorOk;

      // A segment register followed by a colon (':') describes a segment of a
      // memory operand - in such case we store the segment and jump to MemOp.
      AsmToken tTmp;
      if (parser.nextToken(token) == AsmToken::kColon &&
          parser.nextToken(&tTmp) == AsmToken::kLBracket) {
        seg = dst;
        goto MemOp;
      }
      parser.putTokenBack(token);
      return kErrorOk;
    }

    // Try memory size specifier.
    memSize = x86ParseSize(token->data, token->len);
    if (memSize) {
      type = parser.nextToken(token);

      // The specifier may be followed by 'ptr', skip it in such case.
      if (type == AsmToken::kSym &&
          token->len == 3 &&
          StringUtils::toLower<uint32_t>(token->data[0]) == 'p' &&
          StringUtils::toLower<uint32_t>(token->data[1]) == 't' &&
          StringUtils::toLower<uint32_t>(token->data[2]) == 'r') {
        type = parser.nextToken(token);
      }

      // Jump to memory operand if we encountered '['.
      if (type == AsmToken::kLBracket)
        goto MemOp;

      // Parse segment prefix otherwise.
      if (type == AsmToken::kSym) {
        // Segment register.
        if (!x86ParseRegister(seg, token->data, token->len) || !seg.as<X86Reg>().isSeg())
          return DebugUtils::errored(kErrorInvalidAddress);

        type = parser.nextToken(token);
        if (type != AsmToken::kColon)
          return DebugUtils::errored(kErrorInvalidAddress);

        type = parser.nextToken(token);
        if (type == AsmToken::kLBracket)
          goto MemOp;
      }

      return DebugUtils::errored(kErrorInvalidAddress);
    }

    // Must be label/symbol.
    return asmHandleSymbol(parser, dst, token->data, token->len);
  }

  // Memory address - parse opening '['.
  if (type == AsmToken::kLBracket) {
MemOp:
    Operand base;
    Operand index;

    uint32_t shift = 0;
    uint32_t flags = 0;
    uint64_t offset = 0;

    // Parse address prefix - 'abs'.
    type = parser.nextToken(token);
    if (type == AsmToken::kSym) {
      if (token->len == 3) {
        ParserUtils::WordParser addrMode;
        addrMode.addLowercasedChar(token->data, 0);
        addrMode.addLowercasedChar(token->data, 1);
        addrMode.addLowercasedChar(token->data, 2);

        if (addrMode.test('a', 'b', 's')) {
          flags |= Mem::kSignatureMemAbs;
          type = parser.nextToken(token);
        }
        else if (addrMode.test('r', 'e', 'l')) {
          flags |= Mem::kSignatureMemRel;
          type = parser.nextToken(token);
        }
        else if (addrMode.test('w', 'r', 't')) {
          flags |= Mem::kSignatureMemWrt;
          type = parser.nextToken(token);
        }
      }
    }

    // Parse "[base] + [index [* scale]] + [offset]" or "[base + [offset]], [index [* scale]]" parts.
    bool commaSeparated = false;
    uint32_t opType = AsmToken::kAdd;

    for (;;) {
      if (type == AsmToken::kSym) {
        if (opType != AsmToken::kAdd)
          return DebugUtils::errored(kErrorInvalidAddress);

        Operand op;
        if (!x86ParseRegister(op, token->data, token->len)) {
          // No label after 'base' is allowed.
          if (!base.isNone())
            return DebugUtils::errored(kErrorInvalidAddress);

          ASMJIT_PROPAGATE(asmHandleSymbol(parser, op, token->data, token->len));
        }

        type = parser.nextToken(token);
        opType = AsmToken::kInvalid;

        if (type != AsmToken::kMul) {
          // Prefer base, then index.
          if (base.isNone() && !commaSeparated)
            base = op;
          else if (index.isNone())
            index = op;
          else
            return DebugUtils::errored(kErrorInvalidAddress);
          continue;
        }
        else {
          // Must be index.
          if (base.isLabel() || !index.isNone())
            return DebugUtils::errored(kErrorInvalidAddress);

          index = op;
          type = parser.nextToken(token);
          if (type != AsmToken::kU64)
            return DebugUtils::errored(kErrorInvalidAddressScale);

          switch (token->u64) {
            case 1: shift = 0; break;
            case 2: shift = 1; break;
            case 4: shift = 2; break;
            case 8: shift = 3; break;
            default:
              return DebugUtils::errored(kErrorInvalidAddressScale);
          }
        }
      }
      else if (type == AsmToken::kU64) {
        if (opType == AsmToken::kAdd) {
          offset += token->u64;
          opType = AsmToken::kInvalid;
        }
        else if (opType == AsmToken::kSub) {
          offset -= token->u64;
          opType = AsmToken::kInvalid;
        }
        else {
          return DebugUtils::errored(kErrorInvalidAddress);
        }
      }
      else if (type == AsmToken::kAdd) {
        if (opType == AsmToken::kInvalid)
          opType = type;
      }
      else if (type == AsmToken::kSub) {
        if (opType == AsmToken::kInvalid)
          opType = type;
        else
          opType = opType == AsmToken::kSub ? AsmToken::kAdd : AsmToken::kSub;
      }
      else if (type == AsmToken::kRBracket) {
        if (opType != AsmToken::kInvalid)
          return DebugUtils::errored(kErrorInvalidAddress);

        // Reverse base and index if base is a vector register.
        if (X86Reg::isVec(base)) {
          if (index.isReg())
            return DebugUtils::errored(kErrorInvalidAddress);
          std::swap(base, index);
        }

        if (!base.isNone()) {
          if (!IntUtils::isInt32<int64_t>(int64_t(offset)) &&
              !IntUtils::isUInt32<int64_t>(int64_t(offset)))
            return DebugUtils::errored(kErrorInvalidAddress64Bit);

          int32_t disp32 = int32_t(offset & 0xFFFFFFFFU);
          if (base.isLabel())
            dst = x86::ptr(base.as<Label>(), disp32);
          else if (!index.isReg())
            dst = x86::ptr(base.as<X86Gp>(), disp32);
          else
            dst = x86::ptr(base.as<X86Gp>(), index.as<X86Gp>(), shift, disp32);
        }
        else {
          if (!index.isReg())
            dst = x86::ptr(offset);
          else
            dst = x86::ptr(offset, index.as<X86Gp>(), shift);
        }

        dst.as<X86Mem>().setSize(memSize);
        dst._addSignatureData(flags);

        if (seg.isReg())
          dst.as<X86Mem>().setSegment(seg.as<X86Seg>());

        return kErrorOk;
        break;
      }
      else if (type == AsmToken::kComma) {
        if (commaSeparated)
          return DebugUtils::errored(kErrorInvalidAddress);

        opType = AsmToken::kAdd;
        commaSeparated = true;
      }
      else {
        return DebugUtils::errored(kErrorInvalidAddress);
      }

      type = parser.nextToken(token);
    }
  }

  // Immediate.
  if (type == AsmToken::kU64 || type == AsmToken::kSub) {
    bool negative = (type == AsmToken::kSub);
    if (negative) {
      type = parser.nextToken(token);
      if (type != AsmToken::kU64)
        return DebugUtils::errored(kErrorInvalidState);
    }

    dst = imm(negative ? -token->i64 : token->i64);
    return kErrorOk;
  }

  return DebugUtils::errored(kErrorInvalidState);
}

static uint32_t x86ParseInstOption(const uint8_t* s, size_t len) noexcept {
  constexpr uint32_t kX86MinInstOptionLen = 3;
  constexpr uint32_t kX86MaxInstOptionLen = 8;

  if (len < kX86MinInstOptionLen || len > kX86MaxInstOptionLen)
    return 0;

  ParserUtils::WordParser word;

  // Options of length '3':
  word.addLowercasedChar(s, 0);
  word.addLowercasedChar(s, 1);
  word.addLowercasedChar(s, 2);
  if (len == 3) {
    if (word.test('r', 'e', 'p')) return X86Inst::kOptionRep;
    if (word.test('r', 'e', 'x')) return X86Inst::kOptionRex;
    return 0;
  }

  // Options of length '4':
  word.addLowercasedChar(s, 3);
  if (len == 4) {
    if (word.test('l', 'o', 'c', 'k')) return X86Inst::kOptionLock;
    if (word.test('r', 'e', 'p', 'z')) return X86Inst::kOptionRep;
    if (word.test('r', 'e', 'p', 'e')) return X86Inst::kOptionRep;
    if (word.test('l', 'o', 'n', 'g')) return X86Inst::kOptionLongForm;
    if (word.test('v', 'e', 'x', '3')) return X86Inst::kOptionVex3;
    if (word.test('e', 'v', 'e', 'x')) return X86Inst::kOptionEvex;
    return 0;
  }

  // Options of length '5':
  word.addLowercasedChar(s, 4);
  if (len == 5) {
    if (word.test('r', 'e', 'p', 'n', 'e')) return X86Inst::kOptionRepne;
    if (word.test('r', 'e', 'p', 'n', 'z')) return X86Inst::kOptionRepne;
    if (word.test('s', 'h', 'o', 'r', 't')) return X86Inst::kOptionShortForm;
    if (word.test('m', 'o', 'd', 'm', 'r')) return X86Inst::kOptionModMR;
    return 0;
  }

  // Options of length '8':
  word.addLowercasedChar(s, 5);
  word.addLowercasedChar(s, 6);
  word.addLowercasedChar(s, 7);
  if (len == 8) {
    if (word.test('x', 'a', 'c', 'q', 'u', 'i', 'r', 'e')) return X86Inst::kOptionXAcquire;
    if (word.test('x', 'r', 'e', 'l', 'e', 'a', 's', 'e')) return X86Inst::kOptionXRelease;
    return 0;
  }

  return 0;
}

static uint32_t x86ParseAvx512Option(const uint8_t* s, size_t len) noexcept {
  constexpr uint32_t kX86MinAvx512OptionLen = 3;
  constexpr uint32_t kX86MaxAvx512OptionLen = 6;

  if (len < kX86MinAvx512OptionLen || len > kX86MaxAvx512OptionLen)
    return 0;

  ParserUtils::WordParser word;

  // Options of length '3':
  word.addLowercasedChar(s, 0);
  word.addLowercasedChar(s, 1);
  word.addLowercasedChar(s, 2);
  if (len == 3) {
    if (word.test('s', 'a', 'e')) return X86Inst::kOptionSAE;
    return 0;
  }

  if (len < 6)
    return 0;

  // Options of length '6':
  word.addLowercasedChar(s, 3);
  word.addLowercasedChar(s, 4);
  word.addLowercasedChar(s, 5);
  if (len == 6) {
    if (word.test('r', 'n', '-', 's', 'a', 'e')) return X86Inst::kOptionER | X86Inst::kOptionRN_SAE;
    if (word.test('r', 'd', '-', 's', 'a', 'e')) return X86Inst::kOptionER | X86Inst::kOptionRD_SAE;
    if (word.test('r', 'u', '-', 's', 'a', 'e')) return X86Inst::kOptionER | X86Inst::kOptionRU_SAE;
    if (word.test('r', 'z', '-', 's', 'a', 'e')) return X86Inst::kOptionER | X86Inst::kOptionRZ_SAE;
    return 0;
  }

  return 0;
}

static uint32_t x86ParseAvx512Broadcast(const uint8_t* s, size_t len) noexcept {
  constexpr uint32_t kX86MinBcstLen = 4;
  constexpr uint32_t kX86MaxBcstLen = 5;

  if (len < kX86MinBcstLen || len > kX86MaxBcstLen)
    return 0;

  ParserUtils::WordParser word;

  // Broadcast option of length '4':
  word.addLowercasedChar(s, 0);
  word.addLowercasedChar(s, 1);
  word.addLowercasedChar(s, 2);
  word.addLowercasedChar(s, 3);
  if (len == 4) {
    if (word.test('1', 't', 'o', '2')) return X86Mem::kBroadcast1To2;
    if (word.test('1', 't', 'o', '4')) return X86Mem::kBroadcast1To4;
    if (word.test('1', 't', 'o', '8')) return X86Mem::kBroadcast1To8;
    return 0;
  }

  // Broadcast option of length '5':
  word.addLowercasedChar(s, 4);
  if (len == 5) {
    if (word.test('1', 't', 'o', '1', '6')) return X86Mem::kBroadcast1To16;
    if (word.test('1', 't', 'o', '3', '2')) return X86Mem::kBroadcast1To32;
    if (word.test('1', 't', 'o', '6', '4')) return X86Mem::kBroadcast1To64;
    return 0;
  }

  return 0;
}

static uint32_t x86ParseDirective(const uint8_t* s, size_t len) noexcept {
  if (len < 2)
    return 0;

  ParserUtils::WordParser word;
  word.addLowercasedChar(s, 0);
  word.addLowercasedChar(s, 1);

  if (len == 2) {
    if (word.test('d', 'b')) return kX86DirectiveDB;
    if (word.test('d', 'w')) return kX86DirectiveDW;
    if (word.test('d', 'd')) return kX86DirectiveDD;
    if (word.test('d', 'q')) return kX86DirectiveDQ;
    return 0;
  }

  if (len < 5)
    return 0;

  word.addLowercasedChar(s, 2);
  word.addLowercasedChar(s, 3);
  word.addLowercasedChar(s, 4);
  if (len == 5) {
    if (word.test('a', 'l', 'i', 'g', 'n')) return kX86DirectiveAlign;
    return 0;
  }

  return 0;
}

static uint32_t x86ParseAlias(const uint8_t* s, size_t len) noexcept {
  if (len < 3)
    return Inst::kIdNone;

  ParserUtils::WordParser word;
  word.addLowercasedChar(s, 0);
  word.addLowercasedChar(s, 1);
  word.addLowercasedChar(s, 2);
  if (len == 3) {
    if (word.test('s', 'a', 'l')) return X86Inst::kIdShl;
    return Inst::kIdNone;
  }

  word.addLowercasedChar(s, 3);
  if (len == 4) {
    if (word.test('i', 'n', 's', 'b')) return kX86AliasInsb;
    if (word.test('i', 'n', 's', 'w')) return kX86AliasInsw;
    if (word.test('i', 'n', 's', 'd')) return kX86AliasInsd;
    return Inst::kIdNone;
  }

  word.addLowercasedChar(s, 4);
  if (len == 5) {
    if (word.test('c', 'm', 'p', 's', 'b')) return kX86AliasCmpsb;
    if (word.test('c', 'm', 'p', 's', 'w')) return kX86AliasCmpsw;
    if (word.test('c', 'm', 'p', 's', 'd')) return kX86AliasCmpsd;
    if (word.test('c', 'm', 'p', 's', 'q')) return kX86AliasCmpsq;

    if (word.test('l', 'o', 'd', 's', 'b')) return kX86AliasLodsb;
    if (word.test('l', 'o', 'd', 's', 'w')) return kX86AliasLodsw;
    if (word.test('l', 'o', 'd', 's', 'd')) return kX86AliasLodsd;
    if (word.test('l', 'o', 'd', 's', 'q')) return kX86AliasLodsq;

    if (word.test('m', 'o', 'v', 's', 'b')) return kX86AliasMovsb;
    if (word.test('m', 'o', 'v', 's', 'w')) return kX86AliasMovsw;
    if (word.test('m', 'o', 'v', 's', 'd')) return kX86AliasMovsd;
    if (word.test('m', 'o', 'v', 's', 'q')) return kX86AliasMovsq;

    if (word.test('s', 'c', 'a', 's', 'b')) return kX86AliasScasb;
    if (word.test('s', 'c', 'a', 's', 'w')) return kX86AliasScasw;
    if (word.test('s', 'c', 'a', 's', 'd')) return kX86AliasScasd;
    if (word.test('s', 'c', 'a', 's', 'q')) return kX86AliasScasq;

    if (word.test('s', 't', 'o', 's', 'b')) return kX86AliasStosb;
    if (word.test('s', 't', 'o', 's', 'w')) return kX86AliasStosw;
    if (word.test('s', 't', 'o', 's', 'd')) return kX86AliasStosd;
    if (word.test('s', 't', 'o', 's', 'q')) return kX86AliasStosq;

    if (word.test('o', 'u', 't', 's', 'b')) return kX86AliasOutsb;
    if (word.test('o', 'u', 't', 's', 'w')) return kX86AliasOutsw;
    if (word.test('o', 'u', 't', 's', 'd')) return kX86AliasOutsd;

    return Inst::kIdNone;
  }

  word.addLowercasedChar(s, 5);
  if (len == 6) {
    if (word.test('m', 'o', 'v', 'a', 'b', 's')) return kX86AliasMovabs;
  }

  return Inst::kIdNone;
}

static Error x86ParseInstruction(AsmParser& parser, uint32_t& instId, uint32_t& options, AsmToken* token) noexcept {
  for (;;) {
    size_t len = token->len;
    uint8_t lower[32];

    if (len > ASMJIT_ARRAY_SIZE(lower))
      return DebugUtils::errored(kErrorInvalidInstruction);

    strToLower(lower, token->data, len);

    // Try to match instruction alias, as there are some tricky ones.
    instId = x86ParseAlias(lower, len);
    if (instId == Inst::kIdNone) {
      // If that didn't work out, try to match instruction as defined by AsmJit.
      instId = X86Inst::getIdByName(reinterpret_cast<char*>(lower), len);
    }

    if (instId == Inst::kIdNone) {
      // Maybe it's an option / prefix?
      uint32_t option = x86ParseInstOption(lower, len);
      if (!(option))
        return DebugUtils::errored(kErrorInvalidInstruction);

      // Refuse to parse the same option specified multiple times.
      if (ASMJIT_UNLIKELY(options & option))
        return DebugUtils::errored(kErrorOptionAlreadyDefined);

      options |= option;
      if (parser.nextToken(token) != AsmToken::kSym)
        return DebugUtils::errored(kErrorInvalidInstruction);
    }
    else {
      // Ok, we have an instruction. Now let's parse the next token and decide if
      // it belongs to the instruction or not. This is required to parse things
      // such "jmp short" although we prefer "short jmp" (but the former is valid
      // in other assemblers).
      if (parser.nextToken(token) == AsmToken::kSym) {
        len = token->len;
        if (len <= ASMJIT_ARRAY_SIZE(lower)) {
          strToLower(lower, token->data, len);
          uint32_t option = x86ParseInstOption(lower, len);
          if (option == X86Inst::kOptionShortForm) {
            options |= option;
            return kErrorOk;
          }
        }
      }

      parser.putTokenBack(token);
      return kErrorOk;
    }
  }
}

static Error x86FixupInstruction(AsmParser& parser, Inst::Detail& detail, Operand_* operands, uint32_t& count) noexcept {
  uint32_t i;

  uint32_t& instId = detail.instId;
  uint32_t& options = detail.options;

  if (instId >= kX86AliasStart) {
    X86Emitter* emitter = static_cast<X86Emitter*>(parser._emitter);
    uint32_t memSize = 0;
    bool isStr = false;

    switch (instId) {
      case kX86AliasMovabs:
        // 'movabs' is basically the longest 'mov'.
        instId = X86Inst::kIdMov;
        options |= X86Inst::kOptionLongForm;
        break;

      case kX86AliasInsb: memSize = 1; instId = X86Inst::kIdIns; isStr = true; break;
      case kX86AliasInsd: memSize = 4; instId = X86Inst::kIdIns; isStr = true; break;
      case kX86AliasInsw: memSize = 2; instId = X86Inst::kIdIns; isStr = true; break;

      case kX86AliasOutsb: memSize = 1; instId = X86Inst::kIdOuts; isStr = true; break;
      case kX86AliasOutsd: memSize = 4; instId = X86Inst::kIdOuts; isStr = true; break;
      case kX86AliasOutsw: memSize = 2; instId = X86Inst::kIdOuts; isStr = true; break;

      case kX86AliasCmpsb: memSize = 1; instId = X86Inst::kIdCmps; isStr = true; break;
      case kX86AliasCmpsd: memSize = 4;
        isStr = count == 0 || (count == 2 && operands[0].isMem() && operands[1].isMem());
        instId = isStr ? X86Inst::kIdCmps : X86Inst::kIdCmpsd;
        break;
      case kX86AliasCmpsq: memSize = 8; instId = X86Inst::kIdCmps; isStr = true; break;
      case kX86AliasCmpsw: memSize = 2; instId = X86Inst::kIdCmps; isStr = true; break;

      case kX86AliasMovsb: memSize = 1; instId = X86Inst::kIdMovs; isStr = true; break;
      case kX86AliasMovsd: memSize = 4;
        isStr = count == 0 || (count == 2 && operands[0].isMem() && operands[1].isMem());
        instId = isStr ? X86Inst::kIdMovs : X86Inst::kIdMovsd;
        break;
      case kX86AliasMovsq: memSize = 8; instId = X86Inst::kIdMovs; isStr = true; break;
      case kX86AliasMovsw: memSize = 2; instId = X86Inst::kIdMovs; isStr = true; break;

      case kX86AliasLodsb: memSize = 1; instId = X86Inst::kIdLods; isStr = true; break;
      case kX86AliasLodsd: memSize = 4; instId = X86Inst::kIdLods; isStr = true; break;
      case kX86AliasLodsq: memSize = 8; instId = X86Inst::kIdLods; isStr = true; break;
      case kX86AliasLodsw: memSize = 2; instId = X86Inst::kIdLods; isStr = true; break;

      case kX86AliasScasb: memSize = 1; instId = X86Inst::kIdScas; isStr = true; break;
      case kX86AliasScasd: memSize = 4; instId = X86Inst::kIdScas; isStr = true; break;
      case kX86AliasScasq: memSize = 8; instId = X86Inst::kIdScas; isStr = true; break;
      case kX86AliasScasw: memSize = 2; instId = X86Inst::kIdScas; isStr = true; break;

      case kX86AliasStosb: memSize = 1; instId = X86Inst::kIdStos; isStr = true; break;
      case kX86AliasStosd: memSize = 4; instId = X86Inst::kIdStos; isStr = true; break;
      case kX86AliasStosq: memSize = 8; instId = X86Inst::kIdStos; isStr = true; break;
      case kX86AliasStosw: memSize = 2; instId = X86Inst::kIdStos; isStr = true; break;
        break;
    }

    if (isStr) {
      if (count == 0) {
        uint32_t sign = memSize == 1 ? X86Reg::signatureOfT<X86Reg::kRegGpbLo>() :
                        memSize == 2 ? X86Reg::signatureOfT<X86Reg::kRegGpw>() :
                        memSize == 4 ? X86Reg::signatureOfT<X86Reg::kRegGpd>() :
                                       X86Reg::signatureOfT<X86Reg::kRegGpq>() ;

        // String instructions aliases.
        count = 2;
        switch (instId) {
          case X86Inst::kIdCmps: operands[0] = emitter->ptr_zsi(); operands[1] = emitter->ptr_zdi(); break;
          case X86Inst::kIdMovs: operands[0] = emitter->ptr_zdi(); operands[1] = emitter->ptr_zsi(); break;
          case X86Inst::kIdLods:
          case X86Inst::kIdScas: operands[0] = Reg(sign, X86Gp::kIdAx); operands[1] = emitter->ptr_zdi(); break;
          case X86Inst::kIdStos: operands[0] = emitter->ptr_zdi(); operands[1] = Reg(sign, X86Gp::kIdAx); break;
        }
      }

      for (i = 0; i < count; i++) {
        if (operands[i].isMem()) {
          X86Mem& mem = operands[i].as<X86Mem>();

          if (mem.getSize() == 0)
            mem.setSize(memSize);

          if (mem.getBaseId() == X86Gp::kIdDi && mem.getSegmentId() == X86Seg::kIdEs)
            mem.resetSegment();
        }
      }
    }
  }

  for (i = 0; i < count; i++) {
    Operand_& op = operands[i];

    // If the parsed memory segment is the default one, remove it. AsmJit
    // always emits segment-override if the segment is specified, this is
    // good on AsmJit side, but causes problems here as it's not necessary
    // to emit 'ds:' everywhere if the input contains it (and it's common).
    if (op.isMem() && op.as<X86Mem>().hasSegment()) {
      X86Mem& mem = op.as<X86Mem>();

      // Default to `ds` segment for most instructions.
      uint32_t defaultSeg = X86Seg::kIdDs;

      // Default to `ss` segment if the operand has esp|rsp or ebp|rbp base.
      if (mem.hasBaseReg()) {
        if (mem.getBaseId() == X86Gp::kIdSp || mem.getBaseId() == X86Gp::kIdBp)
          defaultSeg = X86Seg::kIdSs;
      }

      if (mem.getSegmentId() == defaultSeg)
        mem.resetSegment();
    }
  }

  return kErrorOk;
}

Error AsmParser::parse(const char* input, size_t len) noexcept {
  setInput(input, len);
  while (!isEndOfInput())
    ASMJIT_PROPAGATE(parseCommand());
  return kErrorOk;
}

Error AsmParser::parseCommand() noexcept {
  AsmToken token;
  uint32_t tType = nextToken(&token);

  _currentCommandOffset = (size_t)(reinterpret_cast<const char*>(token.data) - getInput());

  if (tType == AsmToken::kSym) {
    AsmToken tmp;

    tType = nextToken(&tmp);
    if (tType == AsmToken::kColon) {
      // Parse label.
      Label dst;
      ASMJIT_PROPAGATE(asmHandleSymbol(*this, dst, token.data, token.len));
      ASMJIT_PROPAGATE(_emitter->bind(dst));
      return kErrorOk;
    }

    if (token.data[0] == '.') {
      // Parse directive (instructions never start with '.').
      uint32_t directive = x86ParseDirective(token.data + 1, token.len - 1);

      if (directive == kX86DirectiveAlign) {
        if (tType != AsmToken::kU64)
          return DebugUtils::errored(kErrorInvalidState);

        if (tmp.u64 > std::numeric_limits<uint32_t>::max() || !IntUtils::isPowerOf2(tmp.u64))
          return DebugUtils::errored(kErrorInvalidState);

        ASMJIT_PROPAGATE(_emitter->align(kAlignCode, uint32_t(tmp.u64)));

        tType = nextToken(&token);
        // Fall through as we would like to see EOL or EOF.
      }
      else if (directive >= kX86DirectiveDB && directive <= kX86DirectiveDQ) {
        if (tType != AsmToken::kU64)
          return DebugUtils::errored(kErrorInvalidState);

        uint32_t nBytes   = (directive == kX86DirectiveDB) ? 1 :
                            (directive == kX86DirectiveDW) ? 2 :
                            (directive == kX86DirectiveDD) ? 4 : 8;
        uint64_t maxValue = IntUtils::lsbMask<uint64_t>(nBytes * 8);

        StringBuilderTmp<512> db;
        for (;;) {
          if (tType != AsmToken::kU64)
            return DebugUtils::errored(kErrorInvalidState);

          if (tmp.u64 > maxValue)
            return DebugUtils::errored(kErrorInvalidImmediate);

          db.appendString(reinterpret_cast<const char*>(tmp.valueBytes), nBytes);

          tType = nextToken(&tmp);
          if (tType != AsmToken::kComma)
            break;

          tType = nextToken(&tmp);
        }

        ASMJIT_PROPAGATE(_emitter->embed(db.getData(), db.getLength()));
      }
      else {
        return DebugUtils::errored(kErrorInvalidDirective);
      }
    }
    else {
      // Parse instruction.
      putTokenBack(&tmp);

      Inst::Detail detail;
      ASMJIT_PROPAGATE(x86ParseInstruction(*this, detail.instId, detail.options, &token));

      // Parse operands.
      uint32_t count = 0;
      Operand_ operands[6];
      X86Mem* memOp = nullptr;

      for (;;) {
        tType = nextToken(&token);

        // Instruction without operands...
        if ((tType == AsmToken::kNL || tType == AsmToken::kEnd) && count == 0)
          break;

        // Parse {AVX-512} options that act as operand (valid syntax).
        if (tType == AsmToken::kLCurl) {
          uint32_t kAllowed = X86Inst::kOptionER     |
                              X86Inst::kOptionSAE    |
                              X86Inst::kOptionRN_SAE |
                              X86Inst::kOptionRD_SAE |
                              X86Inst::kOptionRU_SAE |
                              X86Inst::kOptionRZ_SAE ;

          tType = nextToken(&tmp, AsmTokenizer::kParseSymbol | AsmTokenizer::kParseDashes);
          if (tType != AsmToken::kSym && tType != AsmToken::kNSym)
            return DebugUtils::errored(kErrorInvalidState);

          tType = nextToken(&token);
          if (tType != AsmToken::kRCurl)
            return DebugUtils::errored(kErrorInvalidState);

          uint32_t option = x86ParseAvx512Option(tmp.data, tmp.len);
          if (!option || (option & ~kAllowed) != 0)
            return DebugUtils::errored(kErrorInvalidOption);

          uint32_t& options = detail.options;
          if (options & option)
            return DebugUtils::errored(kErrorOptionAlreadyDefined);

          options |= option;
          tType = nextToken(&token);
        }
        else {
          if (count == ASMJIT_ARRAY_SIZE(operands))
            return DebugUtils::errored(kErrorInvalidInstruction);

          // Parse operand.
          ASMJIT_PROPAGATE(x86ParseOperand(*this, operands[count], &token));

          if (operands[count].isMem())
            memOp = static_cast<X86Mem*>(&operands[count]);

          // Parse {AVX-512} option(s) immediately next to the operand.
          tType = nextToken(&token);
          if (tType == AsmToken::kLCurl) {
            uint32_t& options = detail.options;
            do {
              tType = nextToken(&tmp, AsmTokenizer::kParseSymbol | AsmTokenizer::kParseDashes);
              if (tType != AsmToken::kSym && tType != AsmToken::kNSym)
                return DebugUtils::errored(kErrorInvalidState);

              tType = nextToken(&token);
              if (tType != AsmToken::kRCurl)
                return DebugUtils::errored(kErrorInvalidState);

              uint32_t maskRegId = 0;
              uint32_t len = tmp.len;
              const uint8_t* str = tmp.data;

              if (len == 2 && (str[0] == 'k' || str[1] == 'K') && (maskRegId = (str[1] - (uint8_t)'0')) < 8) {
                RegOnly& extraReg = detail.extraReg;
                if (count != 0)
                  return DebugUtils::errored(kErrorInvalidOption);

                if (!extraReg.isNone())
                  return DebugUtils::errored(kErrorOptionAlreadyDefined);

                extraReg.init(X86KReg(maskRegId));
              }
              else if (len == 1 && (str[0] == 'z' || str[1] == 'Z')) {
                if (count != 0)
                  return DebugUtils::errored(kErrorInvalidOption);

                if (options & X86Inst::kOptionZMask)
                  return DebugUtils::errored(kErrorOptionAlreadyDefined);

                options |= X86Inst::kOptionZMask;
              }
              else {
                uint32_t option = x86ParseAvx512Option(str, len);
                if (option) {
                  if (options & option)
                    return DebugUtils::errored(kErrorOptionAlreadyDefined);
                  options |= option;
                }
                else {
                  uint32_t bcst = x86ParseAvx512Broadcast(str, len);
                  if (!bcst)
                    return DebugUtils::errored(kErrorInvalidOption);

                  if (bcst && (!memOp || memOp->hasBroadcast()))
                    return DebugUtils::errored(kErrorInvalidBroadcast);

                  memOp->setBroadcast(bcst);
                }
              }

              tType = nextToken(&token);
            } while (tType == AsmToken::kLCurl);
          }

          count++;
        }

        if (tType == AsmToken::kComma)
          continue;

        if (tType == AsmToken::kNL || tType == AsmToken::kEnd)
          break;

        return DebugUtils::errored(kErrorInvalidState);
      }

      ASMJIT_PROPAGATE(x86FixupInstruction(*this, detail, operands, count));
      ASMJIT_PROPAGATE(Inst::validate(_emitter->getArchType(), detail, operands, count));

      _emitter->setInstOptions(detail.options);
      _emitter->setExtraReg(detail.extraReg);
      ASMJIT_PROPAGATE(_emitter->emitOpArray(detail.instId, operands, count));
    }
  }

  if (tType == AsmToken::kNL)
    return kErrorOk;

  if (tType == AsmToken::kEnd) {
    _endOfInput = true;
    return kErrorOk;
  }

  return DebugUtils::errored(kErrorInvalidState);
}

} // asmtk namespace
