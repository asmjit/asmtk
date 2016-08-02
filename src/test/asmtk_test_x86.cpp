#include <stdio.h>
#include <stdlib.h>
#include "../asmtk/asmtk.h"

static const char asmData[] =
  "mov eax, ebx\n"
  "mov eax, 0xFFFFFFFF\n"
  "mov ax, fs\n"
  "mov fs, ax\n"
  "pand mm0, mm1\n"
  "paddw xmm0, xmm1\n"
  "vpaddw ymm0, ymm1, ymm7\n"
  "mov edx, [rax]\n"
  "mov edx, [rax + 0]\n"
  "mov edx, [rax + 128]\n"
  "mov edx, [rax + rcx]\n"
  "mov edx, [rax + rcx + 128]\n"
  "mov edx, [rax + rcx * 1]\n"
  "mov edx, [rax + rcx * 2 + 32]\n"
  "mov edx, [rax + rcx * 4 + 64]\n"
  "mov edx, [rax + rcx * 8 + 128 + 128]\n"
  "mov edx, fs:[rax]\n"
  ;

int main(int argc, char* argv[]) {
  using namespace asmjit;
  using namespace asmtk;

  FileLogger logger(stdout);
  logger.addOptions(Logger::kOptionBinaryForm);

  CodeHolder holder(ArchInfo::kIdX64);
  holder.setLogger(&logger);

  X86Assembler a(&holder);
  AsmParser p(&a);

  Error err = p.parse(asmData);
  if (err) printf("ERROR: %0.8x (%s)\n", err, DebugUtils::errorAsString(err));

  return 1;
}
