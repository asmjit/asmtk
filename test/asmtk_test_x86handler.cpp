#include <stdint.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "./asmtk.h"

using namespace asmjit;
using namespace asmtk;

static Error ASMJIT_CDECL unknownSymbolHandler(AsmParser* parser, Operand* dst, const char* name, size_t size) {
  void* data = parser->unknownSymbolHandlerData();

  std::printf("SymbolHandler called on symbol '%.*s' (data %p)\n", int(size), name, data);

  if (size == 5 && std::memcmp(name, "TestA", 5) == 0) {
    *dst = x86::rcx;
    return kErrorOk;
  }

  if (size == 5 && std::memcmp(name, "TestB", 5) == 0) {
    *dst = imm(0x4000);
    return kErrorOk;
  }

  // Dst is initially an empty operand (none), if it's not changed AsmTK
  // will create label for it by default. Don't return error in any case
  // as that will terminate the parsing and return immediately.
  return kErrorOk;
}

int main(int argc, char* argv[]) {
  // Initialize CodeInfo with proper architecture and base-address.
  CodeInfo ci;
  ci.init(ArchInfo::kIdX64, 0, uint64_t(0x1000));

  FileLogger logger(stdout);
  logger.addFlags(FormatOptions::kFlagMachineCode);

  // Initialize CodeHolder.
  CodeHolder code;
  Error err = code.init(ci);
  if (err) {
    std::printf("[FAILURE] CodeHolder.init(): %s\n", DebugUtils::errorAsString(err));
    return 1;
  }

  code.setLogger(&logger);
  x86::Assembler a(&code);

  AsmParser parser(&a);
  parser.setUnknownSymbolHandler(unknownSymbolHandler);

  err = parser.parse("mov rax, TestA\n"
                     "call TestB\n");

  if (err) {
    std::printf("[FAILURE] AsmParser.parse(): %s\n", DebugUtils::errorAsString(err));
    return 1;
  }
  else {
    std::printf("[SUCCESS]\n");
    return 0;
  }
}
