// [AsmTk]
// Assembler toolkit based on AsmJit.
//
// [License]
// Zlib - See LICENSE.md file in the package.

// [Dependencies]
#include "./asmparser.h"

namespace asmtk {

using namespace asmjit;

// ============================================================================
// [asmtk::X86RegInfo]
// ============================================================================

// TODO: Information about a register should be part of asmjit.
struct X86RegInfo {
  RegInfo info;
  uint32_t count;
};

#define DEFINE_REG(opType, regType, regKind, regSize, count) \
  {{{ uint8_t(opType), uint8_t(regType), uint8_t(regKind), uint8_t(regSize) }}, count }
static const X86RegInfo x86RegInfo[X86Reg::kRegCount] = {
  DEFINE_REG(Operand::kOpNone, X86Reg::kRegNone        , 0                , 0 , 0  ),
  DEFINE_REG(Operand::kOpNone, X86Reg::kRegNone        , 0                , 0 , 0  ),
  DEFINE_REG(Operand::kOpReg , X86Reg::kRegRip         , X86Reg::kKindRip , 8 , 1  ),
  DEFINE_REG(Operand::kOpReg , X86Reg::kRegSeg         , X86Reg::kKindSeg , 2 , 7  ),
  DEFINE_REG(Operand::kOpReg , X86Reg::kRegGpbLo       , X86Reg::kKindGp  , 1 , 16 ),
  DEFINE_REG(Operand::kOpReg , X86Reg::kRegGpbHi       , X86Reg::kKindGp  , 1 , 4  ),
  DEFINE_REG(Operand::kOpReg , X86Reg::kRegGpw         , X86Reg::kKindGp  , 2 , 16 ),
  DEFINE_REG(Operand::kOpReg , X86Reg::kRegGpd         , X86Reg::kKindGp  , 4 , 16 ),
  DEFINE_REG(Operand::kOpReg , X86Reg::kRegGpq         , X86Reg::kKindGp  , 8 , 16 ),
  DEFINE_REG(Operand::kOpReg , X86Reg::kRegFp          , X86Reg::kKindFp  , 10, 8  ),
  DEFINE_REG(Operand::kOpReg , X86Reg::kRegMm          , X86Reg::kKindMm  , 8 , 8  ),
  DEFINE_REG(Operand::kOpReg , X86Reg::kRegK           , X86Reg::kKindK   , 8 , 8  ),
  DEFINE_REG(Operand::kOpReg , X86Reg::kRegXmm         , X86Reg::kKindVec , 16, 32 ),
  DEFINE_REG(Operand::kOpReg , X86Reg::kRegYmm         , X86Reg::kKindVec , 32, 32 ),
  DEFINE_REG(Operand::kOpReg , X86Reg::kRegZmm         , X86Reg::kKindVec , 64, 32 ),
  DEFINE_REG(Operand::kOpNone, X86Reg::kRegNone        , 0                , 0 , 0  ),
  DEFINE_REG(Operand::kOpReg , X86Reg::kRegBnd         , X86Reg::kKindBnd , 16, 4  ),
  DEFINE_REG(Operand::kOpReg , X86Reg::kRegCr          , X86Reg::kKindCr  , 8 , 9  ),
  DEFINE_REG(Operand::kOpReg , X86Reg::kRegDr          , X86Reg::kKindDr  , 8 , 8  )
};
#undef DEFINE_REG

// ============================================================================
// [asmtk::AsmParser]
// ============================================================================

AsmParser::AsmParser(CodeEmitter* emitter)
  : _emitter(emitter) {}
AsmParser::~AsmParser() {}

// ============================================================================
// [asmtk::AsmParser - Parse]
// ============================================================================

static bool asmParseX86Reg(Operand_& op, const uint8_t* s, size_t len) {
  if (len < 2 || len > 5) return false;
  const uint8_t* sEnd = s + len;

  uint32_t c0 = s[0];
  uint32_t c1 = s[1];
  uint32_t c2 = len > 2 ? s[2] : uint8_t(0);
  uint32_t cn = (c0 << 8) + c1;

  uint32_t regType = X86Reg::kRegNone;
  uint32_t regId = 0;

  static const uint8_t abcdTo0312[] = { 0, 3, 1, 2 };

  // [AL|BL|CL|DL]
  // [AH|BH|CH|DH]
  // [AX|BX|CX|DX]
  // [ES|CS|SS|DS|FS|GS]
  if (len == 2) {
    if (c0 >= 'a' && c0 <= 'd') {
      regId = abcdTo0312[c0 - 'a'];
      if (c1 == 'l') { regType = X86Reg::kRegGpbLo; goto Done; }
      if (c1 == 'h') { regType = X86Reg::kRegGpbHi; goto Done; }
      if (c1 == 'x') { regType = X86Reg::kRegGpw  ; goto Done; }
    }

    if (c1 == 's') {
      regType = X86Reg::kRegSeg;
      if (c0 == 'e') { regId = X86Seg::kIdEs; goto Done; }
      if (c0 == 'c') { regId = X86Seg::kIdCs; goto Done; }
      if (c0 == 's') { regId = X86Seg::kIdSs; goto Done; }
      if (c0 == 'd') { regId = X86Seg::kIdDs; goto Done; }
      if (c0 == 'f') { regId = X86Seg::kIdFs; goto Done; }
      if (c0 == 'g') { regId = X86Seg::kIdGs; goto Done; }
    }

    regType = X86Reg::kRegGpw;
    goto TrySpBpSiDi;
  }

  // [SP|BP|SI|DI]
  // [SPL|BPL|SIL|DIL]
  // [EAX|EBX|ECX|EDX|ESP|EBP|EDI|ESI]
  // [RAX|RBX|RCX|RDX|RSP|RBP|RDI|RSI]
  // [RIP]
  if (len == 3) {
    if (c2 == 'l') {
      regType = X86Reg::kRegGpbLo;
      goto TrySpBpSiDi;
    }

#define COMB_CHAR_2(a, b) ((uint32_t(a) << 8) | uint32_t(b))
    if (c0 == 'e' || c0 == 'r') {
      cn = (c1 << 8) | c2;

      if (c0 == 'r' && cn == COMB_CHAR_2('i', 'p')) {
        regType = X86Reg::kRegRip;
        goto Done;
      }

      regType = (c0 == 'e') ? X86Reg::kRegGpd : X86Reg::kRegGpq;
      if (cn == COMB_CHAR_2('a', 'x')) { regId = X86Gp::kIdAx; goto Done; }
      if (cn == COMB_CHAR_2('d', 'x')) { regId = X86Gp::kIdDx; goto Done; }
      if (cn == COMB_CHAR_2('b', 'x')) { regId = X86Gp::kIdBx; goto Done; }
      if (cn == COMB_CHAR_2('c', 'x')) { regId = X86Gp::kIdCx; goto Done; }
TrySpBpSiDi:
      if (cn == COMB_CHAR_2('s', 'p')) { regId = X86Gp::kIdSp; goto Done; }
      if (cn == COMB_CHAR_2('b', 'p')) { regId = X86Gp::kIdBp; goto Done; }
      if (cn == COMB_CHAR_2('s', 'i')) { regId = X86Gp::kIdSi; goto Done; }
      if (cn == COMB_CHAR_2('d', 'i')) { regId = X86Gp::kIdDi; goto Done; }
    }
#undef COMB_CHAR_2
  }

  // [R?|R?B|R?W|R?D]
  if (c0 == 'r') {
    s++;
    regType = X86Reg::kRegGpq;

    // Handle 'b', 'w', and 'd' suffixes.
    c2 = sEnd[-1];
    if (c2 == 'b')
      regType = X86Reg::kRegGpbLo;
    else if (c2 == 'w')
      regType = X86Reg::kRegGpw;
    else if (c2 == 'd')
      regType = X86Reg::kRegGpd;
    sEnd -= (regType != X86Reg::kRegGpq);
  }
  // [XMM?|YMM?|ZMM?]
  else if (c0 >= 'x' && c0 <= 'z' && c1 == 'm' && c2 == 'm') {
    s += 3;
    regType = X86Reg::kRegXmm + (c0 - 'x');
  }
  // [K?]
  else if (c0 == 'k') {
    s++;
    regType = X86Reg::kRegK;
  }
  // [ST?|FP?]
  else if ((c0 == 's' && c1 == 't') | (c0 == 'f' && c1 == 'p')) {
    s += 2;
    regType = X86Reg::kRegFp;
  }
  // [MM?]
  else if (c0 == 'm' && c1 == 'm') {
    s += 2;
    regType = X86Reg::kRegMm;
  }
  // [BND?]
  else if (c0 == 'b' && c1 == 'n' && c2 == 'd') {
    s += 3;
    regType = X86Reg::kRegBnd;
  }
  // [CR?]
  else if (c0 == 'c' && c1 == 'r') {
    s += 2;
    regType = X86Reg::kRegCr;
  }
  // [DR?]
  else if (c0 == 'd' && c1 == 'r') {
    s += 2;
    regType = X86Reg::kRegDr;
  }
  else {
    return false;
  }

  // Parse the register index.
  regId = static_cast<uint32_t>(s[0]) - '0';
  if (regId >= 10) return false;

  if (++s < sEnd) {
    c0 = static_cast<uint32_t>(*s++) - '0';
    if (c0 >= 10) return false;
    regId = regId * 10 + c0;

    // Maximum register
    if (regId >= 32) return false;
  }

  // Fail if the whole input wasn't parsed.
  if (s != sEnd) return false;

  // Fail if the register index is greater than allowed.
  if (regId >= x86RegInfo[regType].count) return false;

Done:
  op._initReg(x86RegInfo[regType].info.signature, regId);
  return true;
}

static Error asmHandleSymbol(AsmParser& parser, Operand_& dst, const uint8_t* name, size_t len) {
  Label L = parser._emitter->getLabelByName(reinterpret_cast<const char*>(name), len);

  if (!L.isValid()) {
    L = parser._emitter->newNamedLabel(reinterpret_cast<const char*>(name), len);
    if (!L.isValid()) return kErrorNoHeapMemory;
  }

  dst = L;
  return kErrorOk;
}

static Error asmParseX86Operand(AsmParser& parser, Operand_& dst, AsmToken* token) {
  uint32_t type = token->type;
  Operand seg;

  // Register or label - parse a symbol, which could be a register or label reference.
  if (type == AsmToken::kSym) {
    if (asmParseX86Reg(dst, token->data, token->len)) {
      // A segment register followed by a colon (':') describes a segment of a
      // memory operand - in such case we store the segment and jump to MemOp.
      if (static_cast<X86Reg&>(dst).isSeg()) {
        AsmToken tTmp;
        if (parser._tokenizer.next(token) == AsmToken::kColon &&
            parser._tokenizer.next(&tTmp) == AsmToken::kLBracket) {
          seg = dst;
          goto MemOp;
        }
        parser._tokenizer.back(token);
      }
      return kErrorOk;
    }
    else {
      return asmHandleSymbol(parser, dst, token->data, token->len);
    }
  }

  // Memory address - parse opening '['.
  if (type == AsmToken::kLBracket) {
MemOp:
    Operand base;
    Operand index;
    uint32_t shift = 0;
    uint64_t disp = 0;

    // Parse "base + index * scale" part.
    uint32_t opType = AsmToken::kInvalid;
    type = parser._tokenizer.next(token);

    if (type == AsmToken::kSym) {
      if (!asmParseX86Reg(base, token->data, token->len))
        return kErrorInvalidAddress;

      opType = parser._tokenizer.next(token);
      if (opType == AsmToken::kMul) {
        index = base;
        base.reset();
        goto MemMul;
      }
      else if (opType == AsmToken::kAdd) {
        type = parser._tokenizer.next(token);
        if (type == AsmToken::kSym) {
          if (!asmParseX86Reg(index, token->data, token->len))
            return kErrorInvalidAddress;

          opType = parser._tokenizer.next(token);
          if (opType == AsmToken::kMul) {
MemMul:
            type = parser._tokenizer.next(token);
            if (type != AsmToken::kU64)
              return kErrorInvalidAddress;

            switch (token->u64) {
              case 1: shift = 0; break;
              case 2: shift = 1; break;
              case 4: shift = 2; break;
              case 8: shift = 3; break;
              default:
                return kErrorInvalidAddress;
            }
            opType = parser._tokenizer.next(token);
          }
        }
        else if (type == AsmToken::kU64) {
          disp = token->u64;
          opType = parser._tokenizer.next(token);
        }
        else {
          return kErrorInvalidAddress;
        }
      }
      else if (opType == AsmToken::kSub) {
        goto MemDisp;
      }
      else if (opType != AsmToken::kRBracket) {
        return kErrorInvalidAddress;
      }
    }
    else if (type == AsmToken::kAdd || type == AsmToken::kSub) {
      opType = type;
    }
    else if (type == AsmToken::kU64) {
      disp = token->u64;
      opType = parser._tokenizer.next(token);
    }
    else {
      return kErrorInvalidAddress;
    }

    for (;;) {
      // Parse closing ']'.
      if (opType == AsmToken::kRBracket) {
        if (!Utils::isInt32<int64_t>(static_cast<int32_t>(disp)))
          return kErrorInvalidAddress;

        int32_t disp32 = static_cast<int32_t>(static_cast<int64_t>(disp));
        if (base.isReg() && !index.isReg())
          dst = x86::ptr(static_cast<X86Gp&>(base), disp32);
        else if (base.isReg() && index.isReg())
          dst = x86::ptr(static_cast<X86Gp&>(base), static_cast<X86Gp&>(index), shift, disp32);
        else if (!base.isReg() && index.isReg())
          dst = x86::ptr(uint64_t(disp32), static_cast<X86Gp&>(index), shift);
        else
          dst = x86::ptr(uint64_t(disp32));

        if (seg.isReg())
          static_cast<X86Mem&>(dst).setSegment(static_cast<const X86Seg&>(seg));

        return kErrorOk;
      }

      // Displacement.
      if (opType != AsmToken::kAdd && opType != AsmToken::kSub)
        return kErrorInvalidAddress;

MemDisp:
      type = parser._tokenizer.next(token);
      if (type != AsmToken::kU64)
        return kErrorInvalidAddress;

      if (opType == AsmToken::kAdd)
        disp += token->u64;
      else
        disp -= token->u64;

      opType = parser._tokenizer.next(token);
    }
  }

  // Immediate.
  if (type == AsmToken::kU64 || type == AsmToken::kSub) {
    bool negative = (type == AsmToken::kSub);
    if (negative) {
      type = parser._tokenizer.next(token);
      if (type != AsmToken::kU64) return kErrorInvalidState;
    }

    dst = imm(negative ? -token->i64 : token->i64);
    return kErrorOk;
  }

  return kErrorInvalidState;
}

static Error asmParseX86Instruction(AsmParser& parser, uint32_t& instId, uint32_t& options, AsmToken* token) {
  for (;;) {
    // First try to match the instruction as instruction options are unlikely.
    instId = X86Inst::getIdByName(reinterpret_cast<const char*>(token->data), token->len);
    if (instId != kInvalidInst) return kErrorOk;

    // Okay, maybe it's an option?
    if (token->is('s', 'h', 'o', 'r', 't')) {
      if (options & X86Inst::kOptionShortForm)
        return kErrorInvalidInstruction;
      options |= X86Inst::kOptionShortForm;
    }
    else if (token->is('l', 'o', 'n', 'g')) {
      if (options & X86Inst::kOptionLongForm)
        return kErrorInvalidInstruction;
      options |= X86Inst::kOptionLongForm;
    }
    else if (token->is('r', 'e', 'x')) {
      if (options & X86Inst::kOptionRex)
        return kErrorInvalidInstruction;
      options |= X86Inst::kOptionRex;
    }
    else if (token->is('m', 'o', 'd', 'm', 'r')) {
      if (options & X86Inst::kOptionModMR)
        return kErrorInvalidInstruction;
      options |= X86Inst::kOptionModMR;
    }
    else {
      return kErrorInvalidInstruction;
    }

    if (parser._tokenizer.next(token) != AsmToken::kSym)
      return kErrorInvalidInstruction;
  }
}

Error AsmParser::parse(const char* input, size_t len) {
  if (len == kInvalidIndex) len = ::strlen(input);
  if (len == 0) return kErrorOk;
  _tokenizer.setInput(reinterpret_cast<const uint8_t*>(input), len);

  uint32_t archType = _emitter->getArchType();
  for (;;) {
    AsmToken token;
    uint32_t tType = _tokenizer.next(&token);

    if (tType == AsmToken::kSym) {
      AsmToken tmp;

      tType = _tokenizer.next(&tmp);
      if (tType == AsmToken::kColon) {
        // Parse bound label.
        Label dst;
        ASMJIT_PROPAGATE(asmHandleSymbol(*this, dst, token.data, token.len));
        ASMJIT_PROPAGATE(_emitter->bind(dst));

        tType = _tokenizer.next(&token);
      }
      else {
        // Parse instruction.
        _tokenizer.back(&tmp);

        uint32_t instId = 0;
        uint32_t options = 0;
        ASMJIT_PROPAGATE(asmParseX86Instruction(*this, instId, options, &token));

        Operand opExtra;
        Operand opArray[6];
        uint32_t opCount = 0;

        // Parse operands.
        for (;;) {
          tType = _tokenizer.next(&token);

          // Instruction without operands...
          if ((tType == AsmToken::kNL || tType == AsmToken::kEnd) && opCount == 0)
            break;

          // Parse operand.
          ASMJIT_PROPAGATE(asmParseX86Operand(*this, opArray[opCount], &token));

          // Parse {} options introduced by AVX-512.
          tType = _tokenizer.next(&token);
          if (tType == AsmToken::kLCurl) {
            do {
              tType = _tokenizer.next(&token);
              if (tType == AsmToken::kSym || tType == AsmToken::kNSym) {
                if (token.len == 2 && token.data[0] == 'k' && (uint8_t)(token.data[1] - '0') < 8) {
                  if (opCount != 0 || !opExtra.isNone())
                    return kErrorInvalidState;
                  opExtra = X86KReg(token.data[1] - '0');
                  options |= X86Inst::kOptionK;
                }
                else if (token.is('z')) {
                  if (opCount != 0 || (options & X86Inst::kOptionKZ))
                    return kErrorInvalidState;
                  options |= X86Inst::kOptionKZ;
                }
                else if (token.is('1', 't', 'o', 'x')) {
                  if (!opArray[opCount].isMem() || (options & X86Inst::kOption1ToX))
                    return kErrorInvalidState;
                  options |= X86Inst::kOption1ToX;
                }
                else if (token.is('s', 'a', 'e')) {
                  if (opCount != 0 || (options & X86Inst::kOptionSAE))
                    return kErrorInvalidState;
                  options |= X86Inst::kOptionSAE;
                }
                else if (token.is('r', 'n')) {
                  if (opCount != 0 || (options & X86Inst::kOptionER))
                    return kErrorInvalidState;
                  options |= X86Inst::kOptionER | X86Inst::kOptionRN_SAE;
                }
                else if (token.is('r', 'd')) {
                  if (opCount != 0 || (options & X86Inst::kOptionER))
                    return kErrorInvalidState;
                  options |= X86Inst::kOptionER | X86Inst::kOptionRD_SAE;
                }
                else if (token.is('r', 'u')) {
                  if (opCount != 0 || (options & X86Inst::kOptionER))
                    return kErrorInvalidState;
                  options |= X86Inst::kOptionER | X86Inst::kOptionRU_SAE;
                }
                else if (token.is('r', 'z')) {
                  if (opCount != 0 || (options & X86Inst::kOptionER))
                    return kErrorInvalidState;
                  options |= X86Inst::kOptionER | X86Inst::kOptionRZ_SAE;
                }
              }
              else {
                return kErrorInvalidState;
              }

              tType = _tokenizer.next(&token);
              if (tType != AsmToken::kRCurl)
                return kErrorInvalidState;

              tType = _tokenizer.next(&token);
            } while (tType == AsmToken::kLCurl);
          }

          opCount++;
          if (tType == AsmToken::kComma) {
            if (opCount == ASMJIT_ARRAY_SIZE(opArray))
              return kErrorInvalidState;
            continue;
          }

          if (tType == AsmToken::kNL)
            break;

          return kErrorInvalidState;
        }

        ASMJIT_PROPAGATE(X86Inst::validate(archType, instId, options, opExtra, opArray, opCount));
        _emitter->setOptions(options);

        if (opExtra.isReg()) _emitter->setOpExtra(opExtra);
        if (opCount > 4) _emitter->setOp4(opArray[4]);
        if (opCount > 5) _emitter->setOp5(opArray[5]);

        ASMJIT_PROPAGATE(_emitter->_emit(instId, opArray[0], opArray[1], opArray[2], opArray[3]));
      }
    }

    if (tType == AsmToken::kNL)
      continue;

    if (tType == AsmToken::kEnd)
      break;

    return kErrorInvalidState;
  }

  return kErrorOk;
}

} // asmtk namespace
