#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <asmjit/x86.h>
#include "./asmtk.h"

using namespace asmjit;
using namespace asmtk;

static Error ASMJIT_CDECL unknownSymbolHandler(AsmParser* parser, Operand* dst, const char* name, size_t size) {
  void* data = parser->unknownSymbolHandlerData();

  printf("SymbolHandler called on symbol '%.*s' (data %p)\n", int(size), name, data);

  if (size == 5 && memcmp(name, "TestA", 5) == 0) {
    *dst = x86::rcx;
    return kErrorOk;
  }

  if (size == 5 && memcmp(name, "TestB", 5) == 0) {
    *dst = imm(0x4000);
    return kErrorOk;
  }

  // Dst is initially an empty operand (none), if it's not changed AsmTK
  // will create label for it by default. Don't return error in any case
  // as that will terminate the parsing and return immediately.
  return kErrorOk;
}

int main(int argc, char* argv[]) {
  // Initialize Environment with X64 architecture.
  Environment environment;
  environment.init(Arch::kX64);
  uint32_t baseAddress = uint64_t(0x1000);

  FileLogger logger(stdout);
  logger.addFlags(FormatFlags::kMachineCode);

  // Initialize CodeHolder.
  CodeHolder code;
  Error err = code.init(environment, baseAddress);

  if (err) {
    printf("[FAILURE] CodeHolder.init(): %s\n", DebugUtils::errorAsString(err));
    return 1;
  }

  code.setLogger(&logger);
  x86::Assembler a(&code);

  AsmParser parser(&a);
  parser.setUnknownSymbolHandler(unknownSymbolHandler);

  err = parser.parse("mov rax, TestA\ncall TestB\n");
  if (err) {
    printf("[FAILURE] AsmParser.parse(): %s\n", DebugUtils::errorAsString(err));
    return 1;
  }
  else {
    printf("[SUCCESS]\n");
    return 0;
  }
}
