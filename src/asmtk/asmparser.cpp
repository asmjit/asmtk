// [AsmTk]
// Assembler toolkit based on AsmJit.
//
// [License]
// Zlib - See LICENSE.md file in the package.

#define ASMTK_EXPORTS

#include <asmjit/x86.h>

#include "./asmparser.h"
#include "./parserutils.h"

namespace asmtk {

using namespace asmjit;

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
  kX86AliasStart = 0x00010000u,

  kX86AliasInsb = kX86AliasStart,
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
  kX86AliasStosw,

  kX86AliasJrcxz,
};

// ============================================================================
// [asmtk::AsmParser]
// ============================================================================

AsmParser::AsmParser(BaseEmitter* emitter) noexcept
  : _emitter(emitter),
    _current_command_offset(0),
    _current_global_label_id(Globals::kInvalidId),
    _unknown_symbol_handler(nullptr),
    _unknown_symbol_handler_data(nullptr) {}
AsmParser::~AsmParser() noexcept {}

// ============================================================================
// [asmtk::AsmParser - Input]
// ============================================================================

AsmTokenType AsmParser::next_token(AsmToken* token, ParseFlags flags) noexcept {
  return _tokenizer.next(token, flags);
}

void AsmParser::put_token_back(AsmToken* token) noexcept {
  _tokenizer.put_back(token);
}

// ============================================================================
// [asmtk::AsmParser - Parse]
// ============================================================================

static void str_to_lower(uint8_t* dst, const uint8_t* src, size_t size) noexcept{
  for (size_t i = 0; i < size; i++)
    dst[i] = Support::ascii_to_lower<uint8_t>(uint8_t(src[i]));
}

#define COMB_CHAR_2(a, b) \
  ((uint32_t(a) << 8) | uint32_t(b))

#define COMB_CHAR_4(a, b, c, d) \
  ((uint32_t(a) << 24) | (uint32_t(b) << 16) | (uint32_t(c) << 8) | uint32_t(d))

static uint32_t x86_register_count(Arch arch, RegType reg_type) noexcept {
  if (arch == Arch::kX86)
    return 8;

  if (reg_type == RegType::kX86_St || reg_type == RegType::kX86_Mm || reg_type == RegType::kMask || reg_type == RegType::kTile)
    return 8;

  if (reg_type == RegType::kVec128 || reg_type == RegType::kVec256 || reg_type == RegType::kVec512)
    return 32;

  return 16;
}

static bool x86_parse_register(AsmParser& parser, Operand_& op, const uint8_t* s, size_t size) noexcept {
  constexpr uint32_t kMinSize = 2;
  constexpr uint32_t kMaxSize = 5;

  if (size < kMinSize || size > kMaxSize)
    return false;

  const uint8_t* sEnd = s + size;

  uint32_t c0 = Support::ascii_to_lower<uint32_t>(s[0]);
  uint32_t c1 = Support::ascii_to_lower<uint32_t>(s[1]);
  uint32_t c2 = size > 2 ? Support::ascii_to_lower<uint32_t>(s[2]) : uint32_t(0);
  uint32_t cn = (c0 << 8) + c1;

  RegType rType = RegType::kNone;
  uint32_t rId = 0;

  static const uint8_t gp_letter_to_reg_index[] = {
    uint8_t(x86::Gp::kIdAx), // a
    uint8_t(x86::Gp::kIdBx), // b
    uint8_t(x86::Gp::kIdCx), // c
    uint8_t(x86::Gp::kIdDx)  // d
  };

  static const uint8_t sr_letter_to_reg_index[] = {
    uint8_t(Reg::kIdBad), // a
    uint8_t(Reg::kIdBad), // b
    uint8_t(x86::SReg::kIdCs), // c
    uint8_t(x86::SReg::kIdDs), // d
    uint8_t(x86::SReg::kIdEs), // e
    uint8_t(x86::SReg::kIdFs), // f
    uint8_t(x86::SReg::kIdGs), // g
    uint8_t(Reg::kIdBad), // h
    uint8_t(Reg::kIdBad), // i
    uint8_t(Reg::kIdBad), // j
    uint8_t(Reg::kIdBad), // k
    uint8_t(Reg::kIdBad), // l
    uint8_t(Reg::kIdBad), // m
    uint8_t(Reg::kIdBad), // n
    uint8_t(Reg::kIdBad), // o
    uint8_t(Reg::kIdBad), // p
    uint8_t(Reg::kIdBad), // q
    uint8_t(Reg::kIdBad), // r
    uint8_t(x86::SReg::kIdSs)  // s
  };

  // [AL|BL|CL|DL]
  // [AH|BH|CH|DH]
  // [AX|BX|CX|DX]
  // [ES|CS|SS|DS|FS|GS]
  if (size == 2 && Support::is_between<uint32_t>(c0, 'a', 's')) {
    if (c0 <= 'd') {
      rId = gp_letter_to_reg_index[c0 - 'a'];

      rType = RegType::kGp8Lo;
      if (c1 == 'l') goto Done;

      rType = RegType::kGp8Hi;
      if (c1 == 'h') goto Done;

      rType = RegType::kGp16;
      if (c1 == 'x') goto Done;
    }

    if (c1 == 's') {
      rId = sr_letter_to_reg_index[c0 - 'a'];
      rType = RegType::kSegment;

      if (rId != Reg::kIdBad)
        goto Done;
    }

    rType = RegType::kGp16;
    goto TrySpBpSiDi;
  }

  // [SP|BP|SI|DI]
  // [SPL|BPL|SIL|DIL]
  // [EAX|EBX|ECX|EDX|ESP|EBP|EDI|ESI]
  // [RAX|RBX|RCX|RDX|RSP|RBP|RDI|RSI]
  // [RIP]
  if (size == 3) {
    if (c2 == 'l') {
      rType = RegType::kGp8Lo;
      goto TrySpBpSiDi;
    }

    if (c0 == 'e' || c0 == 'r') {
      cn = (c1 << 8) | c2;
      rType = (c0 == 'e') ? RegType::kGp32 : RegType::kGp64;

      if (c0 == 'r' && cn == COMB_CHAR_2('i', 'p')) {
        rType = RegType::kPC;
        goto Done;
      }

      if (cn == COMB_CHAR_2('a', 'x')) { rId = x86::Gp::kIdAx; goto Done; }
      if (cn == COMB_CHAR_2('d', 'x')) { rId = x86::Gp::kIdDx; goto Done; }
      if (cn == COMB_CHAR_2('b', 'x')) { rId = x86::Gp::kIdBx; goto Done; }
      if (cn == COMB_CHAR_2('c', 'x')) { rId = x86::Gp::kIdCx; goto Done; }

TrySpBpSiDi:
      if (cn == COMB_CHAR_2('s', 'p')) { rId = x86::Gp::kIdSp; goto Done; }
      if (cn == COMB_CHAR_2('b', 'p')) { rId = x86::Gp::kIdBp; goto Done; }
      if (cn == COMB_CHAR_2('s', 'i')) { rId = x86::Gp::kIdSi; goto Done; }
      if (cn == COMB_CHAR_2('d', 'i')) { rId = x86::Gp::kIdDi; goto Done; }
    }
  }

  // [R?|R?B|R?W|R?D]
  if (c0 == 'r') {
    s++;
    rType = RegType::kGp64;

    // Handle 'b', 'w', and 'd' suffixes.
    c2 = Support::ascii_to_lower<uint32_t>(sEnd[-1]);
    if (c2 == 'b')
      rType = RegType::kGp8Lo;
    else if (c2 == 'w')
      rType = RegType::kGp16;
    else if (c2 == 'd')
      rType = RegType::kGp32;
    sEnd -= (rType != RegType::kGp64);
  }
  // [XMM?|YMM?|ZMM?]
  else if (c0 >= 'x' && c0 <= 'z' && c1 == 'm' && c2 == 'm') {
    s += 3;
    rType = RegType(uint32_t(RegType::kVec128) + uint32_t(c0 - 'x'));
  }
  // [K?]
  else if (c0 == 'k') {
    s++;
    rType = RegType::kMask;
  }
  // [ST?|FP?]
  else if ((c0 == 's' && c1 == 't') | (c0 == 'f' && c1 == 'p')) {
    s += 2;
    rType = RegType::kX86_St;
  }
  // [MM?]
  else if (c0 == 'm' && c1 == 'm') {
    s += 2;
    rType = RegType::kX86_Mm;
  }
  // [BND?]
  else if (c0 == 'b' && c1 == 'n' && c2 == 'd') {
    s += 3;
    rType = RegType::kX86_Bnd;
  }
  // [TMM?]
  else if (c0 == 't' && c1 == 'm' && c2 == 'm') {
    s += 3;
    rType = RegType::kTile;
  }
  // [CR?]
  else if (c0 == 'c' && c1 == 'r') {
    s += 2;
    rType = RegType::kControl;
  }
  // [DR?]
  else if (c0 == 'd' && c1 == 'r') {
    s += 2;
    rType = RegType::kDebug;
  }
  else {
    return false;
  }

  // Parse the register index.
  rId = uint32_t(s[0]) - '0';
  if (rId >= 10)
    return false;

  if (++s < sEnd) {
    c0 = uint32_t(*s++) - '0';
    if (c0 >= 10)
      return false;
    rId = rId * 10 + c0;

    // Maximum register
    if (rId >= x86_register_count(parser.emitter()->arch(), rType))
      return false;
  }

  // Fail if the whole input wasn't parsed.
  if (s != sEnd)
    return false;

  // Fail if the register index is greater than allowed.
  if (rId >= 32)
    return false;

Done:
  op._init_reg(RegUtils::signature_of(rType), rId);
  return true;
}

static uint32_t x86_parse_size(const uint8_t* s, size_t size) noexcept {
  constexpr uint32_t kMinSize = 4;
  constexpr uint32_t kMaxSize = 7;

  if (size < kMinSize || size > kMaxSize)
    return 0;

  // Start from the end.
  ParserUtils::WordParser suffix;
  suffix.add_lowercased_char(s + size - 4, 0);
  suffix.add_lowercased_char(s + size - 4, 1);
  suffix.add_lowercased_char(s + size - 4, 2);
  suffix.add_lowercased_char(s + size - 4, 3);

  if (suffix.test('w', 'o', 'r', 'd')) {
    // Parsed 'word'.
    if (size == 4)
      return 2;

    // Sizes of length '5':
    ParserUtils::WordParser word_size;
    word_size.add_lowercased_char(s, 0);

    if (size == 5) {
      // Check the most common first.
      if (word_size.test('d')) return 4;
      if (word_size.test('q')) return 8;
      if (word_size.test('o')) return 16;
      if (word_size.test('x')) return 16;
      if (word_size.test('y')) return 32;
      if (word_size.test('z')) return 64;

      // `fword` (aka far word, 16:32 m48 pointer) and `tword` (m80).
      if (word_size.test('f')) return 6;
      if (word_size.test('t')) return 10;
    }

    // Sizes of length '6':
    word_size.add_lowercased_char(s, 1);
    if (size == 6) {
      if (word_size.test('m', 'm')) return 8;
      if (word_size.test('d', 'q')) return 16;
      if (word_size.test('q', 'q')) return 32;
    }

    // Sizes of length '7':
    word_size.add_lowercased_char(s, 2);
    if (size == 7) {
      if (word_size.test('x', 'm', 'm')) return 16;
      if (word_size.test('y', 'm', 'm')) return 32;
      if (word_size.test('z', 'm', 'm')) return 64;
    }
  }

  // Parsed 'byte'.
  if (suffix.test('b', 'y', 't', 'e')) {
    if (size == 4)
      return 1;

    // Sizes of length '5':
    ParserUtils::WordParser word_size;
    word_size.add_lowercased_char(s, 0);

    if (size == 5) {
      if (word_size.test('t')) return 10;
    }
  }

  return 0;
}

static Error handle_symbol(AsmParser& parser, Operand_& dst, const uint8_t* name, size_t name_size) noexcept {
  // Resolve global/local label.
  BaseEmitter* emitter = parser._emitter;

  const uint8_t* local_name = nullptr;
  size_t local_name_size = 0;
  size_t parent_name_size = name_size;

  // Don't do anything if the name starts with "..".
  if (!(name_size >= 2 && name[0] == '.' && name[1] == '.')) {
    local_name = static_cast<const uint8_t*>(memchr(name, '.', name_size));
    if (local_name) {
      parent_name_size = (size_t)(local_name - name);
      local_name++;
      local_name_size = (size_t)((name + name_size) - local_name);
    }
  }

  Label parent;
  Label label;

  if (local_name) {
    if (name[0] == '.')
      parent.set_id(parser._current_global_label_id);
    else
      parent = emitter->label_by_name(reinterpret_cast<const char*>(name), parent_name_size);

    if (parent.is_valid())
      label = emitter->label_by_name(reinterpret_cast<const char*>(local_name), local_name_size, parent.id());
  }
  else {
    label = emitter->label_by_name(reinterpret_cast<const char*>(name), name_size, parent.id());
  }

  if (!label.is_valid()) {
    if (parser._unknown_symbol_handler) {
      dst.reset();
      ASMJIT_PROPAGATE(parser._unknown_symbol_handler(&parser, static_cast<Operand*>(&dst), reinterpret_cast<const char*>(name), name_size));
      if (!dst.is_none())
        return Error::kOk;
    }

    if (local_name) {
      if (!parent.is_valid()) {
        if (!parent_name_size)
          return make_error(Error::kInvalidParentLabel);

        parent = emitter->new_named_label(reinterpret_cast<const char*>(name), parent_name_size, LabelType::kGlobal);
        if (!parent.is_valid())
          return make_error(Error::kOutOfMemory);
      }
      label = emitter->new_named_label(reinterpret_cast<const char*>(local_name), local_name_size, LabelType::kLocal, parent.id());
      if (!label.is_valid())
        return make_error(Error::kOutOfMemory);
    }
    else {
      label = emitter->new_named_label(reinterpret_cast<const char*>(name), name_size, LabelType::kGlobal);
      if (!label.is_valid())
        return make_error(Error::kOutOfMemory);
    }
  }

  dst = label;
  return Error::kOk;
}

static Error x86_parse_operand(AsmParser& parser, Operand_& dst, AsmToken* token) noexcept {
  AsmTokenType type = token->type();
  uint32_t mem_size = 0;
  Operand seg;

  // Symbol, could be register, memory operand size, or label.
  if (type == AsmTokenType::kSym) {
    // Try register.
    if (x86_parse_register(parser, dst, token->data(), token->size())) {
      if (!dst.as<Reg>().is_segment_reg())
        return Error::kOk;

      // A segment register followed by a colon (':') describes a segment of a
      // memory operand - in such case we store the segment and jump to MemOp.
      AsmToken tTmp;
      if (parser.next_token(token) == AsmTokenType::kColon &&
          parser.next_token(&tTmp) == AsmTokenType::kLBracket) {
        seg = dst;
        goto MemOp;
      }
      parser.put_token_back(token);
      return Error::kOk;
    }

    // Try memory size specifier.
    mem_size = x86_parse_size(token->data(), token->size());
    if (mem_size) {
      type = parser.next_token(token);

      // The specifier may be followed by 'ptr', skip it in such case.
      if (type == AsmTokenType::kSym &&
          token->size() == 3 &&
          Support::ascii_to_lower<uint32_t>(token->data_at(0)) == 'p' &&
          Support::ascii_to_lower<uint32_t>(token->data_at(1)) == 't' &&
          Support::ascii_to_lower<uint32_t>(token->data_at(2)) == 'r') {
        type = parser.next_token(token);
      }

      // Jump to memory operand if we encountered '['.
      if (type == AsmTokenType::kLBracket)
        goto MemOp;

      // Parse segment prefix otherwise.
      if (type == AsmTokenType::kSym) {
        // Segment register.
        if (!x86_parse_register(parser, seg, token->data(), token->size()) || !seg.as<Reg>().is_segment_reg())
          return make_error(Error::kInvalidAddress);

        type = parser.next_token(token);
        if (type != AsmTokenType::kColon)
          return make_error(Error::kInvalidAddress);

        type = parser.next_token(token);
        if (type == AsmTokenType::kLBracket)
          goto MemOp;
      }

      return make_error(Error::kInvalidAddress);
    }

    // Must be label/symbol.
    return handle_symbol(parser, dst, token->data(), token->size());
  }

  // Memory address - parse opening '['.
  if (type == AsmTokenType::kLBracket) {
MemOp:
    Operand base;
    Operand index;

    uint32_t shift = 0;
    uint64_t offset = 0;
    OperandSignature signature{0};

    // Parse address prefix - 'abs'.
    type = parser.next_token(token);
    if (type == AsmTokenType::kSym) {
      if (token->size() == 3) {
        ParserUtils::WordParser addr_mode;
        addr_mode.add_lowercased_char(token->data(), 0);
        addr_mode.add_lowercased_char(token->data(), 1);
        addr_mode.add_lowercased_char(token->data(), 2);

        if (addr_mode.test('a', 'b', 's')) {
          signature |= OperandSignature::from_value<x86::Mem::kSignatureMemAddrTypeMask>(x86::Mem::AddrType::kAbs);
          type = parser.next_token(token);
        }
        else if (addr_mode.test('r', 'e', 'l')) {
          signature |= OperandSignature::from_value<x86::Mem::kSignatureMemAddrTypeMask>(x86::Mem::AddrType::kRel);
          type = parser.next_token(token);
        }
      }
    }

    // Parse "[base] + [index [* scale]] + [offset]" or "[base + [offset]], [index [* scale]]".
    bool comma_separated = false;
    AsmTokenType op_type = AsmTokenType::kAdd;

    for (;;) {
      if (type == AsmTokenType::kSym) {
        if (op_type != AsmTokenType::kAdd)
          return make_error(Error::kInvalidAddress);

        Operand op;
        if (!x86_parse_register(parser, op, token->data(), token->size())) {
          // No label after 'base' is allowed.
          if (!base.is_none())
            return make_error(Error::kInvalidAddress);

          ASMJIT_PROPAGATE(handle_symbol(parser, op, token->data(), token->size()));
        }

        type = parser.next_token(token);
        op_type = AsmTokenType::kInvalid;

        if (type != AsmTokenType::kMul) {
          // Prefer base, then index.
          if (base.is_none() && !comma_separated)
            base = op;
          else if (index.is_none())
            index = op;
          else
            return make_error(Error::kInvalidAddress);
          continue;
        }
        else {
          // Must be index.
          if (base.is_label() || !index.is_none())
            return make_error(Error::kInvalidAddress);

          index = op;
          type = parser.next_token(token);
          if (type != AsmTokenType::kU64)
            return make_error(Error::kInvalidAddressScale);

          switch (token->u64_value()) {
            case 1: shift = 0; break;
            case 2: shift = 1; break;
            case 4: shift = 2; break;
            case 8: shift = 3; break;
            default:
              return make_error(Error::kInvalidAddressScale);
          }
        }
      }
      else if (type == AsmTokenType::kU64) {
        if (op_type == AsmTokenType::kAdd) {
          offset += token->u64_value();
          op_type = AsmTokenType::kInvalid;
        }
        else if (op_type == AsmTokenType::kSub) {
          offset -= token->u64_value();
          op_type = AsmTokenType::kInvalid;
        }
        else {
          return make_error(Error::kInvalidAddress);
        }
      }
      else if (type == AsmTokenType::kAdd) {
        if (op_type == AsmTokenType::kInvalid)
          op_type = type;
      }
      else if (type == AsmTokenType::kSub) {
        if (op_type == AsmTokenType::kInvalid)
          op_type = type;
        else
          op_type = op_type == AsmTokenType::kSub ? AsmTokenType::kAdd : AsmTokenType::kSub;
      }
      else if (type == AsmTokenType::kRBracket) {
        if (op_type != AsmTokenType::kInvalid)
          return make_error(Error::kInvalidAddress);

        // Reverse base and index if base is a vector register.
        if (base.is_vec()) {
          if (index.is_reg())
            return make_error(Error::kInvalidAddress);
          std::swap(base, index);
        }

        if (!base.is_none()) {
          // Verify the address can be assigned to the operand.
          if (!Support::is_int_n<32>(int64_t(offset))) {
            if (!Support::is_uint_n<32>(int64_t(offset)))
              return make_error(Error::kInvalidAddress64Bit);

            if (base.as<Reg>().is_reg(RegType::kGp64))
              return make_error(Error::kInvalidAddress64BitZeroExtension);
          }

          int32_t disp32 = int32_t(offset & 0xFFFFFFFFu);
          if (base.is_label())
            dst = x86::ptr(base.as<Label>(), disp32);
          else if (!index.is_reg())
            dst = x86::ptr(base.as<x86::Gp>(), disp32);
          else
            dst = x86::ptr(base.as<x86::Gp>(), index.as<x86::Gp>(), shift, disp32);
        }
        else {
          if (!index.is_reg())
            dst = x86::ptr(offset);
          else
            dst = x86::ptr(offset, index.as<x86::Gp>(), shift);
        }

        dst.as<x86::Mem>().set_size(mem_size);
        dst._signature |= signature;

        if (seg.is_reg())
          dst.as<x86::Mem>().set_segment(seg.as<x86::SReg>());

        return Error::kOk;
      }
      else if (type == AsmTokenType::kComma) {
        if (comma_separated)
          return make_error(Error::kInvalidAddress);

        op_type = AsmTokenType::kAdd;
        comma_separated = true;
      }
      else {
        return make_error(Error::kInvalidAddress);
      }

      type = parser.next_token(token);
    }
  }

  // Immediate.
  if (type == AsmTokenType::kU64 || type == AsmTokenType::kSub) {
    bool negative = (type == AsmTokenType::kSub);
    if (negative) {
      type = parser.next_token(token);
      if (type != AsmTokenType::kU64)
        return make_error(Error::kInvalidState);
    }

    dst = imm(negative ? -token->i64_value() : token->i64_value());
    return Error::kOk;
  }

  return make_error(Error::kInvalidState);
}

static InstOptions x86_parse_inst_option(const uint8_t* s, size_t size) noexcept {
  constexpr uint32_t kMinSize = 3;
  constexpr uint32_t kMaxSize = 8;

  if (size < kMinSize || size > kMaxSize)
    return InstOptions::kNone;

  ParserUtils::WordParser word;

  // Options of length '3':
  word.add_lowercased_char(s, 0);
  word.add_lowercased_char(s, 1);
  word.add_lowercased_char(s, 2);

  if (size == 3) {
    if (word.test('b', 'n', 'd')) return InstOptions::kX86_Repne;
    if (word.test('r', 'e', 'p')) return InstOptions::kX86_Rep;
    if (word.test('r', 'e', 'x')) return InstOptions::kX86_Rex;
    if (word.test('v', 'e', 'x')) return InstOptions::kX86_Vex;

    return InstOptions::kNone;
  }

  // Options of length '4':
  word.add_lowercased_char(s, 3);

  if (size == 4) {
    if (word.test('e', 'v', 'e', 'x')) return InstOptions::kX86_Evex;
    if (word.test('l', 'o', 'c', 'k')) return InstOptions::kX86_Lock;
    if (word.test('l', 'o', 'n', 'g')) return InstOptions::kLongForm;
    if (word.test('r', 'e', 'p', 'e')) return InstOptions::kX86_Rep;
    if (word.test('r', 'e', 'p', 'z')) return InstOptions::kX86_Rep;
    if (word.test('v', 'e', 'x', '3')) return InstOptions::kX86_Vex3;

    return InstOptions::kNone;
  }

  // Options of length '5':
  word.add_lowercased_char(s, 4);

  if (size == 5) {
    if (word.test('m', 'o', 'd', 'r', 'm')) return InstOptions::kX86_ModRM;
    if (word.test('m', 'o', 'd', 'm', 'r')) return InstOptions::kX86_ModMR;
    if (word.test('r', 'e', 'p', 'n', 'e')) return InstOptions::kX86_Repne;
    if (word.test('r', 'e', 'p', 'n', 'z')) return InstOptions::kX86_Repne;
    if (word.test('s', 'h', 'o', 'r', 't')) return InstOptions::kShortForm;

    return InstOptions::kNone;
  }

  // Options of length '8':
  word.add_lowercased_char(s, 5);
  word.add_lowercased_char(s, 6);
  word.add_lowercased_char(s, 7);

  if (size == 8) {
    if (word.test('x', 'a', 'c', 'q', 'u', 'i', 'r', 'e')) return InstOptions::kX86_XAcquire;
    if (word.test('x', 'r', 'e', 'l', 'e', 'a', 's', 'e')) return InstOptions::kX86_XRelease;

    return InstOptions::kNone;
  }

  return InstOptions::kNone;
}

static InstOptions x86_parse_avx512_option(const uint8_t* s, size_t size) noexcept {
  constexpr uint32_t kMinSize = 3;
  constexpr uint32_t kMaxSize = 6;

  if (size < kMinSize || size > kMaxSize)
    return InstOptions::kNone;

  ParserUtils::WordParser word;

  // Options of length '3':
  word.add_lowercased_char(s, 0);
  word.add_lowercased_char(s, 1);
  word.add_lowercased_char(s, 2);

  if (size == 3) {
    if (word.test('s', 'a', 'e')) return InstOptions::kX86_SAE;

    return InstOptions::kNone;
  }

  if (size < 6)
    return InstOptions::kNone;

  // Options of length '6':
  word.add_lowercased_char(s, 3);
  word.add_lowercased_char(s, 4);
  word.add_lowercased_char(s, 5);

  if (size == 6) {
    if (word.test('r', 'n', '-', 's', 'a', 'e')) return InstOptions::kX86_ER | InstOptions::kX86_RN_SAE;
    if (word.test('r', 'd', '-', 's', 'a', 'e')) return InstOptions::kX86_ER | InstOptions::kX86_RD_SAE;
    if (word.test('r', 'u', '-', 's', 'a', 'e')) return InstOptions::kX86_ER | InstOptions::kX86_RU_SAE;
    if (word.test('r', 'z', '-', 's', 'a', 'e')) return InstOptions::kX86_ER | InstOptions::kX86_RZ_SAE;

    return InstOptions::kNone;
  }

  return InstOptions::kNone;
}

static x86::Mem::Broadcast x86_parse_avx512_broadcast(const uint8_t* s, size_t size) noexcept {
  constexpr uint32_t kMinSize = 4;
  constexpr uint32_t kMaxSize = 5;

  if (size < kMinSize || size > kMaxSize)
    return x86::Mem::Broadcast::kNone;

  ParserUtils::WordParser word;

  // Broadcast option of length '4':
  word.add_lowercased_char(s, 0);
  word.add_lowercased_char(s, 1);
  word.add_lowercased_char(s, 2);
  word.add_lowercased_char(s, 3);

  if (size == 4) {
    if (word.test('1', 't', 'o', '2')) return x86::Mem::Broadcast::k1To2;
    if (word.test('1', 't', 'o', '4')) return x86::Mem::Broadcast::k1To4;
    if (word.test('1', 't', 'o', '8')) return x86::Mem::Broadcast::k1To8;

    return x86::Mem::Broadcast::kNone;
  }

  // Broadcast option of length '5':
  word.add_lowercased_char(s, 4);

  if (size == 5) {
    if (word.test('1', 't', 'o', '1', '6')) return x86::Mem::Broadcast::k1To16;
    if (word.test('1', 't', 'o', '3', '2')) return x86::Mem::Broadcast::k1To32;
    if (word.test('1', 't', 'o', '6', '4')) return x86::Mem::Broadcast::k1To64;

    return x86::Mem::Broadcast::kNone;
  }

  return x86::Mem::Broadcast::kNone;
}

static uint32_t x86_parse_directive(const uint8_t* s, size_t size) noexcept {
  if (size < 2)
    return 0;

  ParserUtils::WordParser word;
  word.add_lowercased_char(s, 0);
  word.add_lowercased_char(s, 1);

  if (size == 2) {
    if (word.test('d', 'b')) return kX86DirectiveDB;
    if (word.test('d', 'w')) return kX86DirectiveDW;
    if (word.test('d', 'd')) return kX86DirectiveDD;
    if (word.test('d', 'q')) return kX86DirectiveDQ;
    return 0;
  }

  if (size < 5)
    return 0;

  word.add_lowercased_char(s, 2);
  word.add_lowercased_char(s, 3);
  word.add_lowercased_char(s, 4);
  if (size == 5) {
    if (word.test('a', 'l', 'i', 'g', 'n')) return kX86DirectiveAlign;
    return 0;
  }

  return 0;
}

static uint32_t x86_parse_alias(const uint8_t* s, size_t size) noexcept {
  if (size < 3)
    return x86::Inst::kIdNone;

  ParserUtils::WordParser word;
  word.add_lowercased_char(s, 0);
  word.add_lowercased_char(s, 1);
  word.add_lowercased_char(s, 2);
  if (size == 3) {
    if (word.test('s', 'a', 'l')) return x86::Inst::kIdShl;
    return x86::Inst::kIdNone;
  }

  word.add_lowercased_char(s, 3);
  if (size == 4) {
    if (word.test('i', 'n', 's', 'b')) return kX86AliasInsb;
    if (word.test('i', 'n', 's', 'w')) return kX86AliasInsw;
    if (word.test('i', 'n', 's', 'd')) return kX86AliasInsd;
    return x86::Inst::kIdNone;
  }

  word.add_lowercased_char(s, 4);
  if (size == 5) {
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

    if (word.test('j', 'r', 'c', 'x', 'z')) return kX86AliasJrcxz;

    return x86::Inst::kIdNone;
  }

  return x86::Inst::kIdNone;
}

static Error x86_parse_instruction(AsmParser& parser, InstId& inst_id, InstOptions& options, AsmToken* token) noexcept {
  for (;;) {
    size_t size = token->size();
    uint8_t lower[32];

    if (size > ASMJIT_ARRAY_SIZE(lower))
      return make_error(Error::kInvalidInstruction);

    str_to_lower(lower, token->data(), size);

    // Try to match instruction alias, as there are some tricky ones.
    inst_id = x86_parse_alias(lower, size);
    if (inst_id == x86::Inst::kIdNone) {
      // If that didn't work out, try to match instruction as defined by AsmJit.
      inst_id = InstAPI::string_to_inst_id(parser.emitter()->arch(), reinterpret_cast<char*>(lower), size);
    }

    if (inst_id == x86::Inst::kIdNone) {
      // Maybe it's an option / prefix?
      InstOptions option = x86_parse_inst_option(lower, size);
      if (option == InstOptions::kNone)
        return make_error(Error::kInvalidInstruction);

      // Refuse to parse the same option specified multiple times.
      if (ASMJIT_UNLIKELY(Support::test(options, option)))
        return make_error(Error::kOptionAlreadyDefined);

      options |= option;
      if (parser.next_token(token) != AsmTokenType::kSym)
        return make_error(Error::kInvalidInstruction);
    }
    else {
      // Ok, we have an instruction. Now let's parse the next token and decide if it belongs to the instruction or not.
      // This is required to parse things such "jmp short" although we prefer "short jmp" (but the former is valid in
      // other assemblers).
      if (parser.next_token(token) == AsmTokenType::kSym) {
        size = token->size();
        if (size <= ASMJIT_ARRAY_SIZE(lower)) {
          str_to_lower(lower, token->data(), size);
          InstOptions option = x86_parse_inst_option(lower, size);
          if (option == InstOptions::kShortForm) {
            options |= option;
            return Error::kOk;
          }
        }
      }

      parser.put_token_back(token);
      return Error::kOk;
    }
  }
}

static Error x86_fixup_instruction(AsmParser& parser, BaseInst& inst, Operand_* operands, uint32_t& count) noexcept {
  uint32_t i;

  InstId& inst_id = inst._inst_id;

  if (inst_id >= kX86AliasStart) {
    x86::Emitter* emitter = static_cast<x86::Emitter*>(parser._emitter);
    uint32_t mem_size = 0;
    bool is_str = false;

    switch (inst_id) {
      case kX86AliasInsb: mem_size = 1; inst_id = x86::Inst::kIdIns; is_str = true; break;
      case kX86AliasInsd: mem_size = 4; inst_id = x86::Inst::kIdIns; is_str = true; break;
      case kX86AliasInsw: mem_size = 2; inst_id = x86::Inst::kIdIns; is_str = true; break;

      case kX86AliasOutsb: mem_size = 1; inst_id = x86::Inst::kIdOuts; is_str = true; break;
      case kX86AliasOutsd: mem_size = 4; inst_id = x86::Inst::kIdOuts; is_str = true; break;
      case kX86AliasOutsw: mem_size = 2; inst_id = x86::Inst::kIdOuts; is_str = true; break;

      case kX86AliasCmpsb: mem_size = 1; inst_id = x86::Inst::kIdCmps; is_str = true; break;
      case kX86AliasCmpsd: mem_size = 4;
        is_str = count == 0 || (count == 2 && operands[0].is_mem() && operands[1].is_mem());
        inst_id = is_str ? x86::Inst::kIdCmps : x86::Inst::kIdCmpsd;
        break;
      case kX86AliasCmpsq: mem_size = 8; inst_id = x86::Inst::kIdCmps; is_str = true; break;
      case kX86AliasCmpsw: mem_size = 2; inst_id = x86::Inst::kIdCmps; is_str = true; break;

      case kX86AliasMovsb: mem_size = 1; inst_id = x86::Inst::kIdMovs; is_str = true; break;
      case kX86AliasMovsd: mem_size = 4;
        is_str = count == 0 || (count == 2 && operands[0].is_mem() && operands[1].is_mem());
        inst_id = is_str ? x86::Inst::kIdMovs : x86::Inst::kIdMovsd;
        break;
      case kX86AliasMovsq: mem_size = 8; inst_id = x86::Inst::kIdMovs; is_str = true; break;
      case kX86AliasMovsw: mem_size = 2; inst_id = x86::Inst::kIdMovs; is_str = true; break;

      case kX86AliasLodsb: mem_size = 1; inst_id = x86::Inst::kIdLods; is_str = true; break;
      case kX86AliasLodsd: mem_size = 4; inst_id = x86::Inst::kIdLods; is_str = true; break;
      case kX86AliasLodsq: mem_size = 8; inst_id = x86::Inst::kIdLods; is_str = true; break;
      case kX86AliasLodsw: mem_size = 2; inst_id = x86::Inst::kIdLods; is_str = true; break;

      case kX86AliasScasb: mem_size = 1; inst_id = x86::Inst::kIdScas; is_str = true; break;
      case kX86AliasScasd: mem_size = 4; inst_id = x86::Inst::kIdScas; is_str = true; break;
      case kX86AliasScasq: mem_size = 8; inst_id = x86::Inst::kIdScas; is_str = true; break;
      case kX86AliasScasw: mem_size = 2; inst_id = x86::Inst::kIdScas; is_str = true; break;

      case kX86AliasStosb: mem_size = 1; inst_id = x86::Inst::kIdStos; is_str = true; break;
      case kX86AliasStosd: mem_size = 4; inst_id = x86::Inst::kIdStos; is_str = true; break;
      case kX86AliasStosq: mem_size = 8; inst_id = x86::Inst::kIdStos; is_str = true; break;
      case kX86AliasStosw: mem_size = 2; inst_id = x86::Inst::kIdStos; is_str = true; break;
        break;

      case kX86AliasJrcxz: inst_id = x86::Inst::kIdJecxz; break;
    }

    if (is_str) {
      if (count == 0) {
        OperandSignature reg_signature = OperandSignature{
          mem_size == 1 ? RegTraits<RegType::kGp8Lo>::kSignature :
          mem_size == 2 ? RegTraits<RegType::kGp16 >::kSignature :
          mem_size == 4 ? RegTraits<RegType::kGp32 >::kSignature :
                         RegTraits<RegType::kGp64 >::kSignature
        };

        // String instructions aliases.
        count = 2;
        switch (inst_id) {
          case x86::Inst::kIdCmps: operands[0] = emitter->ptr_zsi(); operands[1] = emitter->ptr_zdi(); break;
          case x86::Inst::kIdMovs: operands[0] = emitter->ptr_zdi(); operands[1] = emitter->ptr_zsi(); break;
          case x86::Inst::kIdLods:
          case x86::Inst::kIdScas: operands[0] = Reg(reg_signature, x86::Gp::kIdAx); operands[1] = emitter->ptr_zdi(); break;
          case x86::Inst::kIdStos: operands[0] = emitter->ptr_zdi(); operands[1] = Reg(reg_signature, x86::Gp::kIdAx); break;
        }
      }

      for (i = 0; i < count; i++) {
        if (operands[i].is_mem()) {
          x86::Mem& mem = operands[i].as<x86::Mem>();

          if (mem.size() == 0)
            mem.set_size(mem_size);

          if (mem.base_id() == x86::Gp::kIdDi && mem.segment_id() == x86::SReg::kIdEs)
            mem.reset_segment();
        }
      }
    }
  }

  for (i = 0; i < count; i++) {
    Operand_& op = operands[i];

    // If the parsed memory segment is the default one, remove it. AsmJit always emits segment-override if the
    // segment is specified, this is good on AsmJit side, but causes problems here as it's not necessary to emit
    // 'ds:' everywhere if the input contains it (and it's common).
    if (op.is_mem() && op.as<x86::Mem>().has_segment()) {
      x86::Mem& mem = op.as<x86::Mem>();

      // Default to `ds` segment for most instructions.
      uint32_t default_segment = x86::SReg::kIdDs;

      // Default to `ss` segment if the operand has esp|rsp or ebp|rbp base.
      if (mem.has_base_reg()) {
        if (mem.base_id() == x86::Gp::kIdSp || mem.base_id() == x86::Gp::kIdBp)
          default_segment = x86::SReg::kIdSs;
      }

      if (mem.segment_id() == default_segment)
        mem.reset_segment();
    }
  }

  return Error::kOk;
}

Error AsmParser::parse(const char* input, size_t size) noexcept {
  set_input(input, size);
  while (!is_end_of_input())
    ASMJIT_PROPAGATE(parse_command());
  return Error::kOk;
}

Error AsmParser::parse_command() noexcept {
  AsmToken token;
  AsmTokenType token_type = next_token(&token);

  _current_command_offset = (size_t)(reinterpret_cast<const char*>(token.data()) - input());

  if (token_type == AsmTokenType::kSym) {
    AsmToken tmp;

    token_type = next_token(&tmp);
    if (token_type == AsmTokenType::kColon) {
      // Parse label.
      Label label;
      ASMJIT_PROPAGATE(handle_symbol(*this, label, token.data(), token.size()));
      ASMJIT_PROPAGATE(_emitter->bind(label));

      // Must be valid if we passed through handle_symbol() and bind().
      LabelEntry& le = _emitter->code()->label_entry_of(label);

      if (le.label_type() == LabelType::kGlobal)
        _current_global_label_id = label.id();

      return Error::kOk;
    }

    if (token.data_at(0) == '.') {
      // Parse directive (instructions never start with '.').
      uint32_t directive = x86_parse_directive(token.data() + 1, token.size() - 1);

      if (directive == kX86DirectiveAlign) {
        if (token_type != AsmTokenType::kU64)
          return make_error(Error::kInvalidState);

        if (tmp.u64_value() > std::numeric_limits<uint32_t>::max() || !Support::is_power_of_2(tmp.u64_value()))
          return make_error(Error::kInvalidState);

        ASMJIT_PROPAGATE(_emitter->align(AlignMode::kCode, uint32_t(tmp.u64_value())));

        token_type = next_token(&token);
        // Fall through as we would like to see EOL or EOF.
      }
      else if (directive >= kX86DirectiveDB && directive <= kX86DirectiveDQ) {
        if (token_type != AsmTokenType::kU64)
          return make_error(Error::kInvalidState);

        uint32_t n_bytes   = (directive == kX86DirectiveDB) ? 1 :
                             (directive == kX86DirectiveDW) ? 2 :
                             (directive == kX86DirectiveDD) ? 4 : 8;
        uint64_t max_value = Support::lsb_mask<uint64_t>(n_bytes * 8);

        StringTmp<512> db;
        for (;;) {
          if (token_type != AsmTokenType::kU64)
            return make_error(Error::kInvalidState);

          if (tmp.u64_value() > max_value)
            return make_error(Error::kInvalidImmediate);

          db.append(tmp.value_chars(), n_bytes);

          token_type = next_token(&tmp);
          if (token_type != AsmTokenType::kComma)
            break;

          token_type = next_token(&tmp);
        }

        ASMJIT_PROPAGATE(_emitter->embed(db.data(), db.size()));
      }
      else {
        return make_error(Error::kInvalidDirective);
      }
    }
    else {
      // Parse instruction.
      put_token_back(&tmp);

      BaseInst inst;
      ASMJIT_PROPAGATE(x86_parse_instruction(*this, inst._inst_id, inst._options, &token));

      // Parse operands.
      uint32_t count = 0;
      Operand_ operands[6];
      x86::Mem* mem_op = nullptr;

      for (;;) {
        token_type = next_token(&token);

        // Instruction without operands...
        if ((token_type == AsmTokenType::kNL || token_type == AsmTokenType::kEnd) && count == 0)
          break;

        // Parse {AVX-512} options that act as operand (valid syntax).
        if (token_type == AsmTokenType::kLCurl) {
          constexpr InstOptions kAllowed =
            InstOptions::kX86_ER     |
            InstOptions::kX86_SAE    |
            InstOptions::kX86_RN_SAE |
            InstOptions::kX86_RD_SAE |
            InstOptions::kX86_RU_SAE |
            InstOptions::kX86_RZ_SAE ;

          token_type = next_token(&tmp, ParseFlags::kParseSymbol | ParseFlags::kIncludeDashes);
          if (token_type != AsmTokenType::kSym && token_type != AsmTokenType::kNSym)
            return make_error(Error::kInvalidState);

          token_type = next_token(&token);
          if (token_type != AsmTokenType::kRCurl)
            return make_error(Error::kInvalidState);

          InstOptions option = x86_parse_avx512_option(tmp.data(), tmp.size());
          if (option == InstOptions::kNone || Support::test(option, ~kAllowed))
            return make_error(Error::kInvalidOption);

          if (inst.has_option(option))
            return make_error(Error::kOptionAlreadyDefined);

          inst.add_options(option);
          token_type = next_token(&token);
        }
        else {
          if (count == ASMJIT_ARRAY_SIZE(operands))
            return make_error(Error::kInvalidInstruction);

          // Parse operand.
          ASMJIT_PROPAGATE(x86_parse_operand(*this, operands[count], &token));

          if (operands[count].is_mem())
            mem_op = static_cast<x86::Mem*>(&operands[count]);

          // Parse {AVX-512} option(s) immediately next to the operand.
          token_type = next_token(&token);
          if (token_type == AsmTokenType::kLCurl) {
            do {
              token_type = next_token(&tmp, ParseFlags::kParseSymbol | ParseFlags::kIncludeDashes);
              if (token_type != AsmTokenType::kSym && token_type != AsmTokenType::kNSym)
                return make_error(Error::kInvalidState);

              token_type = next_token(&token);
              if (token_type != AsmTokenType::kRCurl)
                return make_error(Error::kInvalidState);

              uint32_t mask_reg_id = 0;
              size_t size = tmp.size();
              const uint8_t* str = tmp.data();

              if (size == 2 && (str[0] == 'k' || str[1] == 'K') && (mask_reg_id = (str[1] - (uint8_t)'0')) < 8) {
                RegOnly& extra_reg = inst._extra_reg;
                if (count != 0)
                  return make_error(Error::kInvalidOption);

                if (!extra_reg.is_none())
                  return make_error(Error::kOptionAlreadyDefined);

                extra_reg.init(x86::KReg(mask_reg_id));
              }
              else if (size == 1 && (str[0] == 'z' || str[1] == 'Z')) {
                if (count != 0)
                  return make_error(Error::kInvalidOption);

                if (inst.has_option(InstOptions::kX86_ZMask))
                  return make_error(Error::kOptionAlreadyDefined);

                inst.add_options(InstOptions::kX86_ZMask);
              }
              else {
                InstOptions option = x86_parse_avx512_option(str, size);
                if (option != InstOptions::kNone) {
                  if (inst.has_option(option))
                    return make_error(Error::kOptionAlreadyDefined);
                  inst.add_options(option);
                }
                else {
                  x86::Mem::Broadcast broadcast = x86_parse_avx512_broadcast(str, size);
                  if (broadcast == x86::Mem::Broadcast::kNone)
                    return make_error(Error::kInvalidOption);

                  if (!mem_op || mem_op->has_broadcast())
                    return make_error(Error::kInvalidBroadcast);

                  mem_op->set_broadcast(broadcast);
                }
              }

              token_type = next_token(&token);
            } while (token_type == AsmTokenType::kLCurl);
          }

          count++;
        }

        if (token_type == AsmTokenType::kComma)
          continue;

        if (token_type == AsmTokenType::kNL || token_type == AsmTokenType::kEnd)
          break;

        return make_error(Error::kInvalidState);
      }

      ASMJIT_PROPAGATE(x86_fixup_instruction(*this, inst, operands, count));
      ASMJIT_PROPAGATE(InstAPI::validate(_emitter->arch(), inst, operands, count));

      _emitter->set_inst_options(inst.options());
      _emitter->set_extra_reg(inst.extra_reg());
      ASMJIT_PROPAGATE(_emitter->emit_op_array(inst.inst_id(), operands, count));
    }
  }

  if (token_type == AsmTokenType::kNL)
    return Error::kOk;

  if (token_type == AsmTokenType::kEnd) {
    _end_of_input = true;
    return Error::kOk;
  }

  return make_error(Error::kInvalidState);
}

} // {asmtk}
