#include <stdio.h>
#include <stdlib.h>
#include "./asmtk.h"

using namespace asmjit;
using namespace asmtk;

static void dumpCode(const uint8_t* buf, size_t len) {
  enum { kCharsPerLine = 39 };
  char hex[kCharsPerLine * 2 + 1];

  size_t i = 0;
  while (i < len) {
    size_t j = 0;
    size_t end = len - i < kCharsPerLine ? len - i : size_t(kCharsPerLine);

    end += i;
    while (i < end) {
      uint8_t b0 = buf[i] >> 4;
      uint8_t b1 = buf[i] & 15;

      hex[j++] = b0 < 10 ? '0' + b0 : 'A' + b0 - 10;
      hex[j++] = b1 < 10 ? '0' + b1 : 'A' + b1 - 10;
      i++;
    }

    hex[j] = '\0';
    puts(hex);
  }
}

static Error ASMJIT_CDECL unknownSymbolHandler(AsmParser* parser, Operand* dst, const char* name, size_t len) {
  void* data = parser->getUnknownSymbolHandlerData();

  printf("Unknown symbol handler called on symbol '%.*s' (data %p)\n",
    static_cast<int>(len), name, data);

  if (len == 5 && ::memcmp(name, "TestA", 5) == 0) {
    *dst = x86::rcx;
    return kErrorOk;
  }

  if (len == 5 && ::memcmp(name, "TestB", 5) == 0) {
    *dst = imm(0x4000);
    return kErrorOk;
  }

  // Dst is initially and empty operand (none), if it's not changed AsmTK
  // will create label for it by default. Don't return error in any case
  // as that will terminate the parsing and return immediately.
  return kErrorOk;
}

int main(int argc, char* argv[]) {
  // Initialize CodeInfo with proper architecture and base-address.
  CodeInfo ci;
  ci.init(ArchInfo::kTypeX64, 0, uint64_t(0x1000));

  FileLogger logger(stdout);
  logger.addOptions(Logger::kOptionBinaryForm);

  // Initialize CodeHolder.
  CodeHolder code;
  Error err = code.init(ci);
  if (err) {
    printf("[FAILURE] CodeHolder.init(): %s\n", DebugUtils::errorAsString(err));
    return 1;
  }

  code.setLogger(&logger);
  X86Assembler a(&code);

  AsmParser parser(&a);
  parser.setUnknownSymbolHandler(unknownSymbolHandler);

  err = parser.parse(
    "mov rax, TestA\n"
    "call TestB");

  // Sync Assembler with CodeHolder.
  code.sync();

  if (err) {
    printf("[FAILURE] AsmParser.parse(): %s\n", DebugUtils::errorAsString(err));
    return 1;
  }
  else {
    printf("[SUCCESS]\n");
    return 0;
  }
}
