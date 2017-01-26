#include <stdio.h>
#include <stdlib.h>
#include "./asmtk.h"

using namespace asmjit;
using namespace asmtk;

class CmdLine {
public:
  CmdLine(int argc, const char* const* argv)
    : argc(argc),
      argv(argv) {}

  bool hasKey(const char* key) const {
    for (int i = 0; i < argc; i++)
      if (::strcmp(argv[i], key) == 0)
        return true;
    return false;
  }

  const char* getKey(const char* key) const {
    size_t keyLen = ::strlen(key);
    size_t argLen = 0;

    const char* arg = NULL;
    for (int i = 0; i <= argc; i++) {
      if (i == argc)
        return NULL;

      arg = argv[i];
      argLen = ::strlen(arg);
      if (argLen >= keyLen && ::memcmp(arg, key, keyLen) == 0)
        break;
    }

    if (argLen > keyLen && arg[keyLen] == '=')
      return arg + keyLen + 1;
    else
      return arg + keyLen;
  }

  int argc;
  const char* const* argv;
};

static bool hexToU64(uint64_t& out, const char* src, size_t len) {
  uint64_t val = 0;
  for (size_t i = 0; i < len; i++) {
    uint32_t c = src[i];
    if (c >= '0' && c <= '9')
      c = c - '0';
    else if (c >= 'a' && c <= 'f')
      c = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F')
      c = c - 'A' + 10;
    else
      return false;
    val = (val << 4) | c;
  }

  out = val;
  return true;
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
  CmdLine cmd(argc, argv);
  const char* archArg = cmd.getKey("--arch");
  const char* baseArg = cmd.getKey("--base");

  uint32_t archType = ArchInfo::kTypeX64;
  uint64_t baseAddress = Globals::kNoBaseAddress;

  if (archArg) {
    if (::strcmp(archArg, "x86") == 0) {
      archType = ArchInfo::kTypeX86;
    }
    else if (::strcmp(archArg, "x64") == 0) {
      archType = ArchInfo::kTypeX64;
    }
    else {
      printf("Invalid --arch parameter\n");
      return 1;
    }
  }
  else {
    archArg = "x64";
  }

  if (baseArg) {
    size_t len = ::strlen(baseArg);
    size_t maxLen = archType == ArchInfo::kTypeX64 ? 16 : 8;

    if (!len || len > maxLen || !hexToU64(baseAddress, baseArg, len)) {
      printf("Invalid --base parameter\n");
      return 1;
    }
  }

  printf("===============================================================\n");
  printf("AsmTk [Assembler toolkit based on AsmJit]\n"                      );
  printf("  - A simple command-line based instruction encoder\n"            );
  printf("  - Architecture=%s [select by --arch=x86|x64]\n", archArg        );
  printf("  - Base-Address=%s [select by --base=hex]\n", baseArg            );
  printf("---------------------------------------------------------------\n");
  printf("Input:\n"                                                         );
  printf("  - Enter instruction and its operands to be encoded.\n"          );
  printf("  - Enter '.clear' to clear everything.\n"                        );
  printf("  - Enter '.print' to print the current code.\n"                  );
  printf("  - Enter '' (empty string) to exit.\n"                           );
  printf("===============================================================\n");

  StringLogger logger;
  logger.addOptions(Logger::kOptionBinaryForm);

  CodeInfo ci(archType, 0, baseAddress);
  CodeHolder code;

  code.init(ci);
  code.setLogger(&logger);

  X86Assembler a(&code);
  AsmParser p(&a);

  char input[4096];
  for (;;) {
    fgets(input, 4095, stdin);
    if (input[0] == 0) break;

    if (isCommand(input, ".clear")) {
      code.reset(false);  // Detaches everything.
      code.init(ci);
      code.setLogger(&logger);
      code.attach(&a);
      continue;
    }

    if (isCommand(input, ".print")) {
      code.sync(); // First sync with the assembler.

      CodeBuffer& buffer = code.getSectionEntry(0)->getBuffer();
      dumpCode(buffer.getData(), buffer.getLength());
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
      fprintf(stdout, "ERROR: 0x%08X: %s\n", err, DebugUtils::errorAsString(err));
    }
  }

  return 0;
}
