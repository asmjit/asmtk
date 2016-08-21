#include <stdio.h>
#include <stdlib.h>
#include "../asmtk/asmtk.h"

using namespace asmjit;
using namespace asmtk;

static uint32_t detectArch(int argc, char* argv[]) {
  for (int i = 1; i < argc; i++) {
    if (::strcmp(argv[i], "--x86") == 0)
      return Arch::kTypeX86;
    if (::strcmp(argv[i], "--x64") == 0)
      return Arch::kTypeX64;
  }
  return Arch::kTypeX64;
}

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

static bool isSpace(const char c) {
  return c == ' ' || c == '\r' || c == '\n' || c == '\t';
}

static bool isCommand(const char* str, const char* cmd) {
  while (str[0] && isSpace(str[0])) str++;

  size_t sLen = ::strlen(str);
  while (sLen && isSpace(str[sLen - 1])) sLen--;

  size_t cLen = ::strlen(cmd);
  return sLen == cLen && ::memcmp(str, cmd, sLen) == 0;
}

int main(int argc, char* argv[]) {
  uint32_t archType = detectArch(argc, argv);
  const char* archString = archType == Arch::kTypeX86 ? "x86" : "x64";

  fprintf(stdout, "=========================================================\n" );
  fprintf(stdout, "AsmTk [Assembler toolkit based on AsmJit]\n"                 );
  fprintf(stdout, "  - A simple command-line based instruction encoder\n"       );
  fprintf(stdout, "  - Architecture=%s (select by --x86 or --x64]\n", archString);
  fprintf(stdout, "---------------------------------------------------------\n" );
  fprintf(stdout, "Input:\n"                                                    );
  fprintf(stdout, "  - Enter instruction and its operands to be encoded.\n"     );
  fprintf(stdout, "  - Enter '.clear' to clear everything.\n"                   );
  fprintf(stdout, "  - Enter '.print' to print the current code.\n"             );
  fprintf(stdout, "  - Enter '' (empty string) to exit.\n"                      );
  fprintf(stdout, "=========================================================\n" );

  StringLogger logger;
  logger.addOptions(Logger::kOptionBinaryForm);

  CodeHolder code;

  code.init(CodeInfo(archType));
  code.setLogger(&logger);

  X86Assembler a(&code);
  AsmParser p(&a);

  char input[4096];
  for (;;) {
    fgets(input, 4095, stdin);
    if (input[0] == 0) break;

    if (isCommand(input, ".clear")) {
      code.reset(false);  // Detaches everything.
      code.init(CodeInfo(archType));
      code.setLogger(&logger);
      code.attach(&a);
      continue;
    }

    if (isCommand(input, ".print")) {
      code.sync(); // First sync with the assembler.

      CodeBuffer& buffer = code.getSectionEntry(0)->buffer;
      dumpCode(buffer.data, buffer.length);
      continue;
    }

    logger.clearString();
    Error err = p.parse(input);

    if (err == kErrorOk) {
      const char* log = logger.getString();
      size_t i, len = logger.getLength();

      // Skip the instruction part, and keep only the comment part.
      for (i = 0; i < len; i++) {
        if (log[i] == ';') {
          i += 2;
          break;
        }
      }

      if (i < len)
        printf("%.*s", (int)(len - i), log + i);
    }
    else {
      a.resetLastError();
      fprintf(stdout, "ERROR: 0x%0.8X: %s\n", err, DebugUtils::errorAsString(err));
    }
  }

  return 0;
}
