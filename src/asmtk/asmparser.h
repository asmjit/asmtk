// [AsmTk]
// Assembler toolkit based on AsmJit.
//
// [License]
// Zlib - See LICENSE.md file in the package.

#ifndef _ASMTK_ASMPARSER_H
#define _ASMTK_ASMPARSER_H

#include "./strtod.h"
#include "./asmtokenizer.h"

namespace asmtk {

// ============================================================================
// [asmtk::AsmParser]
// ============================================================================

//! Asm parser.
class AsmParser {
public:
  typedef Error (ASMJIT_CDECL* UnknownSymbolHandler)(
    AsmParser* parser, asmjit::Operand* out, const char* name, size_t size);

  asmjit::BaseEmitter* _emitter;
  AsmTokenizer _tokenizer;

  size_t _current_command_offset;
  uint32_t _current_global_label_id;
  bool _end_of_input;

  UnknownSymbolHandler _unknown_symbol_handler;
  void* _unknown_symbol_handler_data;

  //! \name Construction & Destruction
  //! \{

  ASMTK_API AsmParser(asmjit::BaseEmitter* emitter) noexcept;
  ASMTK_API ~AsmParser() noexcept;

  //! \}

  //! \name Accessors
  //! \{

  inline asmjit::BaseEmitter* emitter() const noexcept { return _emitter; }

  //! \}

  //! \name Input Buffer
  //! \{

  inline const char* input() const noexcept {
    return reinterpret_cast<const char*>(_tokenizer._input);
  }

  inline bool set_input(const char* input, size_t size = SIZE_MAX) noexcept {
    if (size == SIZE_MAX)
      size = strlen(input);

    _tokenizer.set_input(reinterpret_cast<const uint8_t*>(input), size);
    _current_command_offset = 0;
    _end_of_input = (size == 0);

    return _end_of_input;
  }

  inline bool is_end_of_input() const noexcept { return _end_of_input; }
  inline size_t current_command_offset() const noexcept { return _current_command_offset; }

  ASMTK_API AsmTokenType next_token(AsmToken* token, ParseFlags flags = ParseFlags::kNone) noexcept;
  ASMTK_API void put_token_back(AsmToken* token) noexcept;

  //! \}

  //! \name Unknown Symbol Handler
  //! \{

  inline UnknownSymbolHandler unknown_symbol_handler() const noexcept { return _unknown_symbol_handler; }
  inline void* unknown_symbol_handler_data() const noexcept { return _unknown_symbol_handler_data; }

  inline void set_unknown_symbol_handler(UnknownSymbolHandler handler, void* data = nullptr) noexcept {
    _unknown_symbol_handler = handler;
    _unknown_symbol_handler_data = data;
  }

  inline void reset_unknown_symbol_handler() noexcept {
    set_unknown_symbol_handler((UnknownSymbolHandler)nullptr, nullptr);
  }

  //! \}

  //! \name Parser
  //! \{

  //! Universal method that setups the input and then calls `parse_command()` until the end is reached. It
  //! returns `Error::kOk` on success (which means that all commands were parsed successfully), otherwise
  //! and error code describing the problem.
  ASMTK_API Error parse(const char* input, size_t size = SIZE_MAX) noexcept;

  ASMTK_API Error parse_command() noexcept;

  //! \}
};

} // {asmtk}

#endif // _ASMTK_ASMPARSER_H
