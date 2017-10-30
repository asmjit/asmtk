#include <stdint.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "./asmtk.h"
#include "./cmdline.h"

using namespace asmjit;
using namespace asmtk;

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

  size_t sLen = std::strlen(str);
  while (sLen && isSpace(str[sLen - 1])) sLen--;

  size_t cLen = std::strlen(cmd);
  return sLen == cLen && std::memcmp(str, cmd, sLen) == 0;
}

int main(int argc, char* argv[]) {
  CmdLine cmd(argc, argv);
  const char* archArg = cmd.getKey("--arch");
  const char* baseArg = cmd.getKey("--base");

  uint32_t archType = ArchInfo::kTypeX64;
  uint64_t baseAddress = Globals::kNoBaseAddress;

  if (archArg) {
    if (std::strcmp(archArg, "x86") == 0) {
      archType = ArchInfo::kTypeX86;
    }
    else if (std::strcmp(archArg, "x64") == 0) {
      archType = ArchInfo::kTypeX64;
    }
    else {
      std::printf("Invalid --arch parameter\n");
      return 1;
    }
  }
  else {
    archArg = "x64";
  }

  if (baseArg) {
    size_t len = std::strlen(baseArg);
    size_t maxLen = archType == ArchInfo::kTypeX64 ? 16 : 8;

    if (!len || len > maxLen || !hexToU64(baseAddress, baseArg, len)) {
      std::printf("Invalid --base parameter\n");
      return 1;
    }
  }

  std::printf("===============================================================\n");
  std::printf("AsmTk [Assembler toolkit based on AsmJit]\n"                      );
  std::printf("  - A simple command-line based instruction encoder\n"            );
  std::printf("  - Architecture=%s [select by --arch=x86|x64]\n", archArg        );
  std::printf("  - Base-Address=%s [select by --base=hex]\n", baseArg            );
  std::printf("---------------------------------------------------------------\n");
  std::printf("Input:\n"                                                         );
  std::printf("  - Enter instruction and its operands to be encoded.\n"          );
  std::printf("  - Enter '.clear' to clear everything.\n"                        );
  std::printf("  - Enter '.print' to print the current code.\n"                  );
  std::printf("  - Enter '.exit' (or Ctrl+D) to exit.\n"                         );
  std::printf("===============================================================\n");

  StringLogger logger;
  logger.addOptions(Logger::kOptionBinaryForm);

  CodeInfo ci(archType, 0, baseAddress);
  CodeHolder code;

  code.init(ci);
  code.setLogger(&logger);

  X86Assembler a(&code);
  AsmParser p(&a);

  char input[4096];
  input[4095] = 0;

  for (;;) {
    // fgets returns NULL on EOF.
    if (std::fgets(input, 4095, stdin) == NULL)
      break;

    size_t len = std::strlen(input);
    if (len > 0 && input[len - 1] == 0x0A)
      input[--len] = 0;

    if (len == 0)
      continue;

    if (isCommand(input, ".exit"))
      break;

    if (isCommand(input, ".clear")) {
      // Detaches everything.
      code.reset(false);
      code.init(ci);
      code.setLogger(&logger);
      code.attach(&a);
      continue;
    }

    if (isCommand(input, ".print")) {
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
        std::printf("%.*s", (int)(len - i), log + i);
    }
    else {
      std::fprintf(stdout, "ERROR: 0x%08X: %s\n", err, DebugUtils::errorAsString(err));
    }
  }

  return 0;
}
