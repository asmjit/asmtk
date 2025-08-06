#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <asmjit/x86.h>
#include "./asmtk.h"

using namespace asmjit;
using namespace asmtk;

static Error ASMJIT_CDECL unknown_symbol_handler(AsmParser* parser, Operand* dst, const char* name, size_t size) {
  void* data = parser->unknown_symbol_handler_data();

  printf("SymbolHandler called on symbol '%.*s' (data %p)\n", int(size), name, data);

  if (size == 5 && memcmp(name, "TestA", 5) == 0) {
    *dst = x86::rcx;
    return Error::kOk;
  }

  if (size == 5 && memcmp(name, "TestB", 5) == 0) {
    *dst = imm(0x4000);
    return Error::kOk;
  }

  // Dst is initially an empty operand (none), if it's not changed AsmTK
  // will create label for it by default. Don't return error in any case
  // as that will terminate the parsing and return immediately.
  return Error::kOk;
}

int main(int argc, char* argv[]) {
  // Initialize Environment with X64 architecture.
  Environment environment;
  environment.init(Arch::kX64);
  uint64_t base_address = uint64_t(0x1000);

  FileLogger logger(stdout);
  logger.add_flags(FormatFlags::kMachineCode);

  // Initialize CodeHolder.
  CodeHolder code;
  Error err = code.init(environment, base_address);

  if (err != Error::kOk) {
    printf("[FAILURE] CodeHolder.init(): %s\n", DebugUtils::error_as_string(err));
    return 1;
  }

  code.set_logger(&logger);
  x86::Assembler a(&code);

  AsmParser parser(&a);
  parser.set_unknown_symbol_handler(unknown_symbol_handler);

  err = parser.parse("mov rax, TestA\ncall TestB\n");
  if (err != Error::kOk) {
    printf("[FAILURE] AsmParser.parse(): %s\n", DebugUtils::error_as_string(err));
    return 1;
  }
  else {
    printf("[SUCCESS]\n");
    return 0;
  }
}
