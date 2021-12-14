#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <asmjit/x86.h>
#include "./asmtk.h"
#include "./cmdline.h"

using namespace asmjit;
using namespace asmtk;

struct TestEntry {
  uint64_t baseAddress;
  Arch arch;
  uint8_t mustPass;
  uint8_t asmSize;
  uint8_t mcSize;
  char machineCode[16];
  char asmString[64];
};

#define X86_PASS(BASE, MACHINE_CODE, ASM_STRING) { \
  BASE,                                            \
  Arch::kX86,                                      \
  true,                                            \
  uint8_t(sizeof(ASM_STRING  ) - 1),               \
  uint8_t(sizeof(MACHINE_CODE) - 1),               \
  MACHINE_CODE,                                    \
  ASM_STRING                                       \
}

#define X86_FAIL(BASE, ASM_STRING) {               \
  BASE,                                            \
  Arch::kX86,                                      \
  false,                                           \
  uint8_t(sizeof(ASM_STRING  ) - 1),               \
  0,                                               \
  "",                                              \
  ASM_STRING                                       \
}

#define X64_PASS(BASE, MACHINE_CODE, ASM_STRING) { \
  BASE,                                            \
  Arch::kX64,                                      \
  true,                                            \
  uint8_t(sizeof(ASM_STRING  ) - 1),               \
  uint8_t(sizeof(MACHINE_CODE) - 1),               \
  MACHINE_CODE,                                    \
  ASM_STRING                                       \
}

#define X64_FAIL(BASE, ASM_STRING) {               \
  BASE,                                            \
  Arch::kX64,                                      \
  false,                                           \
  uint8_t(sizeof(ASM_STRING  ) - 1),               \
  0,                                               \
  "",                                              \
  ASM_STRING                                       \
}

#define RELOC_BASE_ADDRESS Globals::kNoBaseAddress

// Some tests are unique, some were derived from other assembler tests:
//   - Capstone - https://github.com/aquynh/capstone
//   - XEDParse - https://github.com/x64dbg/XEDParse
//   - LLVM     - https://github.com/llvm/llvm-project/tree/master/llvm/test/MC/X86
static const TestEntry testEntries[] = {
  // 32-bit constants parsing.
  X86_PASS(RELOC_BASE_ADDRESS, "\xB8\x00\x00\x00\x00"                             , "mov eax, 0"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xB8\x00\x00\x00\x00"                             , "mov eax, 00"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xB8\xE8\x03\x00\x00"                             , "mov eax, 1000"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xB8\xE8\x03\x00\x00"                             , "mov eax, $3E8"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xB8\xE8\x03\x00\x00"                             , "mov eax, $03E8"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xB8\xE8\x03\x00\x00"                             , "mov eax, 0x3E8"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xB8\xE8\x03\x00\x00"                             , "mov eax, 3E8h"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xB8\xE8\x03\x00\x00"                             , "mov eax, 03E8h"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xB8\xE8\x03\x00\x00"                             , "mov eax, 1750o"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xB8\xE8\x03\x00\x00"                             , "mov eax, 1750q"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xB8\xE8\x03\x00\x00"                             , "mov eax, 01750"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xB8\xE8\x03\x00\x00"                             , "mov eax, 01750o"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xB8\xE8\x03\x00\x00"                             , "mov eax, 01750q"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xB8\xE8\x03\x00\x00"                             , "mov eax, 1111101000b"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xB8\xE8\x03\x00\x00"                             , "mov eax, 01111101000b"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xB8\xE8\x03\x00\x00"                             , "mov eax, 0b1111101000"),

  // 64-bit constants parsing.
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\xC7\xC3\x00\x00\x00\x00"                     , "mov rbx, 0"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\xBB\x88\x77\x66\x55\x44\x33\x22\x11"         , "mov rbx, 0x001122334455667788"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\xBB\x00\x00\x00\x00\x00\x00\x00\x00"         , "long mov rbx, 0"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\xBB\x00\x00\x00\x00\x00\x00\x00\x00"         , "movabs rbx, 0"),

  // 32-bit base instructions.
  X86_PASS(RELOC_BASE_ADDRESS, "\x88\xC4"                                         , "mov ah, al"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x88\xC6"                                         , "mov dh, al"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x89\xD8"                                         , "mov EAX, Ebx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x8B\xC3"                                         , "modrm mov eax, ebx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xB8\xFF\xFF\xFF\xFF"                             , "mov eax, 0xFFFFFFFF"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x8C\xE0"                                         , "mov eax, fs"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x8E\xE0"                                         , "mov fs, eax"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x8B\x10"                                         , "mov edx, [eax]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x8B\x10"                                         , "mov edx, [eax + 0]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x8B\x90\x80\x00\x00\x00"                         , "mov edx, [eax + 128]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x8B\x14\x08"                                     , "mov edx, [eax + ecx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x8B\x94\x08\x80\x00\x00\x00"                     , "mov edx, [eax + ecx + 128]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x8B\x14\x08"                                     , "mov edx, [eax + ecx * 1]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x8B\x54\x48\x20"                                 , "mov edx, [eax + ecx * 2 + 32]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x8B\x54\x88\x40"                                 , "mov edx, [eax + ecx * 4 + 64]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x8B\x94\xC8\x00\x01\x00\x00"                     , "mov edx, [eax + ecx * 8 + 128 + 128]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x8B\x14\x08"                                     , "mov edx, [eax      , ecx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x8B\x14\x08"                                     , "mov edx, [eax +   0, ecx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x8B\x94\x08\x80\x00\x00\x00"                     , "mov edx, [eax + 128, ecx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x8B\x14\x08"                                     , "mov edx, [eax      , ecx * 1]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x8B\x14\x08"                                     , "mov edx, [eax +   0, ecx * 1]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x8B\x54\x48\x20"                                 , "mov edx, [eax +  32, ecx * 2]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x8B\x54\xC8\x02"                                 , "mov edx, [eax + 1+1, ecx * 8]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x64\x8B\x10"                                     , "mov edx, fs:[eax]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x64\xA1\x2C\x00\x00\x00"                         , "mov eax, fs:[0x2C]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x64\x8B\x15\x2C\x00\x00\x00"                     , "mov edx, fs:[0x2C]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x65\x8B\x15\x2C\x00\x00\x00"                     , "mov edx, gs:[0x2C]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x64\xA3\x2C\x00\x00\x00"                         , "mov fs:[0x2C], eax"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x64\x89\x15\x2C\x00\x00\x00"                     , "mov fs:[0x2C], edx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x65\x89\x15\x2C\x00\x00\x00"                     , "mov gs:[0x2C], edx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x20\xC0"                                     , "mov eax, cr0"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF0\x0F\x20\xC0"                                 , "mov eax, cr8"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xA3\x44\x33\x22\x11"                             , "mov [0x11223344], eax"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x89\x05\x44\x33\x22\x11"                         , "modmr mov [0x11223344], eax"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x89\x1D\x44\x33\x22\x11"                         , "mov [0x11223344], ebx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\xBE\x07"                                     , "movsx eax, byte ptr [edi]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\xBF\x07"                                     , "movsx eax, word ptr [edi]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\xB6\x07"                                     , "movzx eax, byte ptr [edi]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\xB6\xC6"                                     , "movzx eax, dh"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\xB7\x07"                                     , "movzx eax, word ptr [edi]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x8D\x05\x00\x00\x00\x00"                         , "lea eax, [0]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF0\x01\x18"                                     , "lock add [eax], ebx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF0\x0F\xC1\x38"                                 , "lock xadd [eax], edi"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x50"                                             , "push eax"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x51"                                             , "push ecx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x52"                                             , "push edx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x53"                                             , "push ebx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x54"                                             , "push esp"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x55"                                             , "push ebp"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x56"                                             , "push esi"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x57"                                             , "push edi"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0E"                                             , "push cs"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x16"                                             , "push ss"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x1E"                                             , "push ds"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x06"                                             , "push es"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\xA0"                                         , "push fs"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\xA8"                                         , "push gs"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\xBA\x20\x01"                             , "bt word ptr [eax], 1"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\xBA\x20\x01"                                 , "bt dword ptr [eax], 1"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xFE\x00"                                         , "inc byte ptr [eax]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\xFF\x00"                                     , "inc word ptr [eax]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xFF\x00"                                         , "inc dword ptr [eax]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF6\xD8"                                         , "neg al"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF6\xDC"                                         , "neg ah"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF7\xD8"                                         , "neg eax"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF7\xD0"                                         , "not eax"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x95\xC3"                                     , "setnz bl"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x94\xC7"                                     , "setz bh"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF2\x0F\x38\xF0\xC7"                             , "crc32 eax, bh"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\xF2\x0F\x38\xF1\xC3"                         , "crc32 eax, bx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF2\x0F\x38\xF1\xC1"                             , "crc32 eax, ecx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF2\x0F\x38\xF0\x06"                             , "crc32 eax, byte ptr [esi]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\xF2\x0F\x38\xF1\x06"                         , "crc32 eax, word ptr [esi]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF2\x0F\x38\xF1\x06"                             , "crc32 eax, dword ptr [esi]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF6\x00\xFF"                                     , "test byte ptr [eax], 0xFF"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\xF7\x00\xFF\x00"                             , "test word ptr [eax], 0xFF"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF7\x00\xFF\x00\x00\x00"                         , "test dword ptr [eax], 0xFF"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xA8\x36"                                         , "test al, 0x36"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF6\xC4\x36"                                     , "test ah, 0x36"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xFF\x10"                                         , "call [eax]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xFF\x10"                                         , "call dword ptr [eax]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\xC5\x01"                                     , "lds ax , [ecx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC5\x01"                                         , "lds eax, [ecx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\xC4\x01"                                     , "les ax , [ecx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC4\x01"                                         , "les eax, [ecx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\xB4\x01"                                 , "lfs ax , [ecx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\xB4\x01"                                     , "lfs eax, [ecx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\xB5\x01"                                 , "lgs ax , [ecx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\xB5\x01"                                     , "lgs eax, [ecx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\xB2\x01"                                 , "lss ax , [ecx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\xB2\x01"                                     , "lss eax, [ecx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC8\x01\x00\x02"                                 , "enter 1, 2"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC9"                                             , "leave"),

  // 64-bit base instructions.
  X64_PASS(RELOC_BASE_ADDRESS, "\x88\xC4"                                         , "mov ah, al"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x88\xC6"                                         , "mov dh, al"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xB8\xE8\x03\x00\x00"                             , "mov eax, 1000"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x20\xC0"                                     , "mov rax, cr0"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x44\x0F\x20\xC0"                                 , "mov rax, cr8"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\x8B\x05\x00\x00\x00\x00"                     , "mov rax, [rip]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x4A\x8B\x04\x60"                                 , "mov rax, [rax + r12 * 2]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x4A\x8B\x04\x68"                                 , "mov rax, [rax + r13 * 2]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x4A\x8B\x84\x60\x00\x01\x00\x00"                 , "mov rax, [rax + r12 * 2 + 256]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x64\x8B\x04\x25\x2C\x00\x00\x00"                 , "mov eax, fs:[0x2C]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x64\x8B\x14\x25\x2C\x00\x00\x00"                 , "mov edx, fs:[0x2C]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x64\x89\x04\x25\x2C\x00\x00\x00"                 , "mov fs:[0x2C], eax"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x64\x89\x14\x25\x2C\x00\x00\x00"                 , "mov fs:[0x2C], edx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x89\x04\x25\x44\x33\x22\x11"                     , "mov [0x11223344], eax"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x89\x1C\x25\x44\x33\x22\x11"                     , "mov [0x11223344], ebx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xA3\x88\x77\x66\x55\x44\x33\x22\x11"             , "mov [0x1122334455667788], eax"),
  X64_PASS(0x1122334455667788, "\x89\x05\xFA\xFF\xFF\xFF"                         , "mov [0x1122334455667788], eax"),
  X64_PASS(0x1122334455667788, "\x89\x05\xFA\xFF\xFF\xFF"                         , "mov [rel 0x1122334455667788], eax"),
  X64_PASS(0x1122334455667788, "\xA3\x88\x77\x66\x55\x44\x33\x22\x11"             , "mov [abs 0x1122334455667788], eax"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\xA1\xEF\xCD\xAB\x89\x67\x45\x23\x01"         , "movabs rax, [0x123456789ABCDEF]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\xBE\x07"                                     , "movsx eax, byte ptr [rdi]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\x0F\xBE\x07"                                 , "movsx rax, byte ptr [rdi]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\xBF\x07"                                     , "movsx eax, word ptr [rdi]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\x0F\xBF\x07"                                 , "movsx rax, word ptr [rdi]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\x63\x07"                                     , "movsxd rax, [rdi]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\x63\x07"                                     , "movsxd rax, dword ptr [rdi]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x63\xC3"                                     , "movsxd ax, bx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x63\xC3"                                         , "movsxd eax, ebx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\x63\xC3"                                     , "movsxd rax, ebx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\xB6\xC6"                                     , "movzx eax, dh"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\xB6\x07"                                     , "movzx eax, byte ptr [rdi]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\x0F\xB6\x07"                                 , "movzx rax, byte ptr [rdi]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x44\x0F\xB6\xFA"                                 , "movzx r15d, dl"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x44\x0F\xB6\xFD"                                 , "movzx r15d, bpl"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\xB7\x07"                                     , "movzx eax, word ptr [rdi]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\x0F\xB7\x07"                                 , "movzx rax, word ptr [rdi]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x8D\x04\x25\x00\x00\x00\x00"                     , "lea eax, [0]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\x8D\x04\x25\x00\x00\x00\x00"                 , "lea rax, [0]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF0\x01\x18"                                     , "lock add [rax], ebx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF0\x48\x0F\xC1\x38"                             , "lock xadd [rax], rdi"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\xA0"                                         , "push fs"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\xA8"                                         , "push gs"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x40\x0F\xA8"                                     , "rex push gs"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\xC8"                                     , "bswap ax"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\xC8"                                         , "bswap eax"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\x0F\xC8"                                     , "bswap rax"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\xBA\x20\x01"                             , "bt word ptr [rax], 1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\xBA\x20\x01"                                 , "bt dword ptr [rax], 1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\x0F\xBA\x20\x01"                             , "bt qword ptr [rax], 1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xFE\x00"                                         , "inc byte ptr [rax]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\xFF\x00"                                     , "inc word ptr [rax]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xFF\x00"                                         , "inc dword ptr [rax]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\xFF\x00"                                     , "inc qword ptr [rax]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x41\x13\x51\xFD"                                 , "adc edx, dword ptr ds:[r9-3]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF6\xD8"                                         , "neg al"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF6\xDC"                                         , "neg ah"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x40\xF6\xDE"                                     , "neg sil"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF7\xD8"                                         , "neg eax"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF7\xD0"                                         , "not eax"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x95\xC3"                                     , "setnz bl"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x94\xC7"                                     , "setz bh"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x40\x0F\x94\xC0"                                 , "rex setz al"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x41\x0F\x94\xC7"                                 , "setz r15b"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF2\x0F\x38\xF0\xC7"                             , "crc32 eax, bh"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\xF2\x0F\x38\xF1\xC3"                         , "crc32 eax, bx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF2\x0F\x38\xF1\xC1"                             , "crc32 eax, ecx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF2\x0F\x38\xF0\x06"                             , "crc32 eax, byte ptr [rsi]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\xF2\x0F\x38\xF1\x06"                         , "crc32 eax, word ptr [rsi]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF2\x0F\x38\xF1\x06"                             , "crc32 eax, dword ptr [rsi]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF2\x48\x0F\x38\xF0\xC3"                         , "crc32 rax, bl"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF2\x48\x0F\x38\xF1\xC1"                         , "crc32 rax, rcx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF2\x48\x0F\x38\xF0\x06"                         , "crc32 rax, byte ptr [rsi]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF2\x48\x0F\x38\xF1\x06"                         , "crc32 rax, qword ptr [rsi]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF6\x00\xFF"                                     , "test byte ptr [rax], 0xFF"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\xF7\x00\xFF\x00"                             , "test word ptr [rax], 0xFF"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF7\x00\xFF\x00\x00\x00"                         , "test dword ptr [rax], 0xFF"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\xF7\x00\xFF\x00\x00\x00"                     , "test qword ptr [rax], 0xFF"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xA8\x36"                                         , "test al, 0x36"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF6\xC4\x36"                                     , "test ah, 0x36"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xFF\x10"                                         , "call [rax]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xFF\x10"                                         , "call qword ptr [rax]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\xB4\x01"                                 , "lfs ax , [rcx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\xB4\x01"                                     , "lfs eax, [rcx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\x0F\xB4\x01"                                 , "lfs rax, [rcx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\xB5\x01"                                 , "lgs ax , [rcx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\xB5\x01"                                     , "lgs eax, [rcx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\x0F\xB5\x01"                                 , "lgs rax, [rcx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\xB2\x01"                                 , "lss ax , [rcx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\xB2\x01"                                     , "lss eax, [rcx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\x0F\xB2\x01"                                 , "lss rax, [rcx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC8\x01\x00\x02"                                 , "enter 1, 2"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x40\xC8\x01\x00\x02"                             , "rex enter 1, 2"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC9"                                             , "leave"),

  // 32-bit NOP.
  X86_PASS(RELOC_BASE_ADDRESS, "\x90"                                             , "nop"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\x1F\x04\x00"                             , "nop word ptr [eax+eax]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\x1F\x04\x00"                             , "nop word ptr [eax+eax], ax"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\x1F\x1C\x00"                             , "nop word ptr [eax+eax], bx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x1F\x04\x00"                                 , "nop dword ptr [eax+eax]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x1F\x04\x00"                                 , "nop dword ptr [eax+eax], eax"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x1F\x1C\x00"                                 , "nop dword ptr [eax+eax], ebx"),

  // 64-bit NOP.
  X64_PASS(RELOC_BASE_ADDRESS, "\x90"                                             , "nop"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\x1F\x04\x00"                             , "nop word ptr [rax+rax]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\x1F\x04\x00"                             , "nop word ptr [rax+rax], ax"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\x1F\x1C\x00"                             , "nop word ptr [rax+rax], bx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x1F\x04\x00"                                 , "nop dword ptr [rax+rax]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x1F\x04\x00"                                 , "nop dword ptr [rax+rax], eax"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x1F\x1C\x00"                                 , "nop dword ptr [rax+rax], ebx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\x0F\x1F\x04\x00"                             , "nop qword ptr [rax+rax]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\x0F\x1F\x04\x00"                             , "nop qword ptr [rax+rax], rax"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\x0F\x1F\x1C\x00"                             , "nop qword ptr [rax+rax], rbx"),

  // 32-bit XACQUIRE|XRELEASE|RTM.
  X86_PASS(RELOC_BASE_ADDRESS, "\xC7\xF8\xFA\xFF\xFF\xFF"                         , "L1: xbegin L1"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC6\xF8\x11"                                     , "xabort 0x11"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF2\xF0\x01\x08"                                 , "xacquire lock add dword [eax], ecx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\xF0\x01\x08"                                 , "xrelease lock add dword [eax], ecx"),

  // 64-bit XACQUIRE|XRELEASE|RTM.
  X64_PASS(RELOC_BASE_ADDRESS, "\xC7\xF8\xFA\xFF\xFF\xFF"                         , "L1: xbegin L1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC6\xF8\x11"                                     , "xabort 0x11"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF2\xF0\x48\x01\x08"                             , "xacquire lock add qword [rax], rcx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\xF0\x48\x01\x08"                             , "xrelease lock add qword [rax], rcx"),

  // 32-bit BMI+ instructions.
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\xF3\x0F\xB8\xC2"                             , "popcnt ax, dx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\xB8\xC2"                                 , "popcnt eax, edx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\xF3\x0F\xBD\xC2"                             , "lzcnt ax, dx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\xBD\xC2"                                 , "lzcnt eax, edx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\xF3\x0F\xBC\xC2"                             , "tzcnt ax, dx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\xBC\xC2"                                 , "tzcnt eax, edx"),

  // 64-bit BMI+ instructions.
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\xF3\x0F\xB8\xC2"                             , "popcnt ax, dx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\xF3\x45\x0F\xB8\xC1"                         , "popcnt r8w, r9w"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\xB8\xC2"                                 , "popcnt eax, edx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\x48\x0F\xB8\xC2"                             , "popcnt rax, rdx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\xF3\x0F\xBD\xC2"                             , "lzcnt ax, dx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\xF3\x45\x0F\xBD\xC7"                         , "lzcnt r8w, r15w"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\xBD\xC2"                                 , "lzcnt eax, edx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\x49\x0F\xBD\xC2"                             , "lzcnt rax, r10"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\xF3\x0F\xBC\xC2"                             , "tzcnt ax, dx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\xF3\x45\x0F\xBC\xC7"                         , "tzcnt r8w, r15w"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\xBC\xC2"                                 , "tzcnt eax, edx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\x4D\x0F\xBC\xFA"                             , "tzcnt r15, r10"),

  // 32-bit LEA with various addressing options.
  X86_PASS(RELOC_BASE_ADDRESS, "\x67\x66\x8D\x00"                                 , "lea ax, [bx + si]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x67\x66\x8D\x01"                                 , "lea ax, [bx + di]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x67\x66\x8D\x02"                                 , "lea ax, [bp + si]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x67\x66\x8D\x03"                                 , "lea ax, [bp + di]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x67\x66\x8D\x04"                                 , "lea ax, [si]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x67\x66\x8D\x05"                                 , "lea ax, [di]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x67\x66\x8D\x46\x00"                             , "lea ax, [bp]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x67\x66\x8D\x07"                                 , "lea ax, [bx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x67\x66\x8D\x40\x10"                             , "lea ax, [bx + si + 0x10]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x67\x66\x8D\x41\x20"                             , "lea ax, [bx + di + 0x20]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x67\x66\x8D\x42\x40"                             , "lea ax, [bp + si + 0x40]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x67\x66\x8D\x43\x60"                             , "lea ax, [bp + di + 0x60]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x67\x66\x8D\x84\x80\x00"                         , "lea ax, [si + 0x80]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x67\x66\x8D\x85\xA0\x00"                         , "lea ax, [di + 0xA0]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x67\x66\x8D\x86\xC0\x00"                         , "lea ax, [bp + 0xC0]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x67\x66\x8D\x87\xFF\x01"                         , "lea ax, [bx + 0x01FF]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x67\x8D\x00"                                     , "lea eax, [bx + si]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x67\x8D\x01"                                     , "lea eax, [bx + di]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x8D\x04\x33"                                     , "lea eax, [ebx + esi]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x8D\x04\x3B"                                     , "lea eax, [ebx + edi]"),

  // 64-bit LEA with various addressing options.
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\x8D\x04\x33"                                 , "lea rax, [rbx + rsi]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\x8D\x04\x3B"                                 , "lea rax, [rbx + rdi]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\x8D\x84\x00\x00\x40\x00\x00"                 , "lea rax, [rax + rax * 1 + 0x4000]"),

  // 32-bit FPU instructions.
  X86_PASS(RELOC_BASE_ADDRESS, "\x9B"                                             , "fwait"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xD8\x00"                                         , "fadd dword ptr [eax]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xDC\x00"                                         , "fadd qword ptr [eax]"),

  // 64-bit FPU instructions.
  X64_PASS(RELOC_BASE_ADDRESS, "\x9B"                                             , "fwait"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xD8\x00"                                         , "fadd dword ptr [rax]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xDC\x00"                                         , "fadd qword ptr [rax]"),

  // 32-bit BND instructions
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\x1A\xCA"                                 , "bndmov bnd1, bnd2"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF2\x0F\x1A\xCF"                                 , "bndcu bnd1, edi"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x1A\x04\x08"                                 , "bndldx bnd0, [eax + ecx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x1B\x0C\x08"                                 , "bndstx [eax + ecx], bnd1"),

  // 64-bit BND instructions
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\x1A\xCA"                                 , "bndmov bnd1, bnd2"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF2\x0F\x1A\xCF"                                 , "bndcu bnd1, rdi"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x1A\x04\x08"                                 , "bndldx bnd0, [rax + rcx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x1B\x0C\x08"                                 , "bndstx [rax + rcx], bnd1"),

  // 32-bit MMX+ and SSE+ instructions.
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x6F\xC1"                                     , "movq mm0, mm1"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x6E\x00"                                     , "movd mm0, [eax]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x6F\x04\x18"                                 , "movq mm0, [eax + ebx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x7E\x38"                                     , "movd [eax], mm7"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x7F\x04\x18"                                 , "movq [eax + ebx], mm0"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\xDB\xC1"                                     , "pand mm0, mm1"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\x7E\xC1"                                 , "movq xmm0, xmm1"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\x6E\x04\x18"                             , "movd xmm0, [eax + ebx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\x7E\x04\x18"                             , "movq xmm0, [eax + ebx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\x7E\x0C\x18"                             , "movd [eax + ebx], xmm1"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\xD6\x0C\x18"                             , "movq [eax + ebx], xmm1"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\xDB\xC1"                                 , "pand xmm0, xmm1"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\xFD\xC1"                                 , "paddw xmm0, xmm1"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x28\x04\x98"                                 , "movaps xmm0, [eax + ebx * 4]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\x28\x04\x98"                             , "movapd xmm0, [eax + ebx * 4]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\x6F\x04\x98"                             , "movdqa xmm0, [eax + ebx * 4]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x29\x0C\x98"                                 , "movaps [eax + ebx * 4], xmm1"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\x29\x0C\x98"                             , "movapd [eax + ebx * 4], xmm1"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\x7F\x0C\x98"                             , "movdqa [eax + ebx * 4], xmm1"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\x3A\x41\xC1\x00"                         , "dppd xmm0, xmm1, 0"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\x2D\xC1"                                 , "cvtss2si eax, xmm1"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF2\x0F\x2D\xC1"                                 , "cvtsd2si eax, xmm1"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\x2A\xC2"                                 , "cvtsi2ss xmm0, edx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF2\x0F\x2A\xC2"                                 , "cvtsi2sd xmm0, edx"),

  // 64-bit MMX+ and SSE+ instructions.
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x6F\xC1"                                     , "movq mm0, mm1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x6E\x00"                                     , "movd mm0, [rax]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x6F\x04\x18"                                 , "movq mm0, [rax + rbx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x7E\x38"                                     , "movd [rax], mm7"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x7F\x04\x18"                                 , "movq [rax + rbx], mm0"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\xDB\xC1"                                     , "pand mm0, mm1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\x7E\xC1"                                 , "movq xmm0, xmm1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\x6E\x04\x18"                             , "movd xmm0, [rax + rbx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\x7E\x04\x18"                             , "movq xmm0, [rax + rbx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\x7E\x0C\x18"                             , "movd [rax + rbx], xmm1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\xD6\x0C\x18"                             , "movq [rax + rbx], xmm1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\xDB\xC1"                                 , "pand xmm0, xmm1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\xFD\xC1"                                 , "paddw xmm0, xmm1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x28\x04\x98"                                 , "movaps xmm0, [rax + rbx * 4]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\x28\x04\x98"                             , "movapd xmm0, [rax + rbx * 4]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\x6F\x04\x98"                             , "movdqa xmm0, [rax + rbx * 4]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x29\x0C\x98"                                 , "movaps [rax + rbx * 4], xmm1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\x29\x0C\x98"                             , "movapd [rax + rbx * 4], xmm1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\x7F\x0C\x98"                             , "movdqa [rax + rbx * 4], xmm1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x45\x0F\x3A\x41\xD3\x00"                     , "dppd xmm10, xmm11, 0"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\x2D\xC1"                                 , "cvtss2si eax, xmm1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\x48\x0F\x2D\xC1"                             , "cvtss2si rax, xmm1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF2\x0F\x2D\xC1"                                 , "cvtsd2si eax, xmm1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF2\x48\x0F\x2D\xC1"                             , "cvtsd2si rax, xmm1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\x2A\xC2"                                 , "cvtsi2ss xmm0, edx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\x48\x0F\x2A\xC2"                             , "cvtsi2ss xmm0, rdx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF2\x0F\x2A\xC2"                                 , "cvtsi2sd xmm0, edx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF2\x48\x0F\x2A\xC2"                             , "cvtsi2sd xmm0, rdx"),

  // 32-bit AVX+ and AVX512+ instructions.
  X86_PASS(RELOC_BASE_ADDRESS, "\xC5\xF9\x6E\x5A\x10"                             , "vmovd xmm3, dword ptr [edx+0x10]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC5\xFA\x7E\x5A\x10"                             , "vmovq xmm3, qword ptr [edx+0x10]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC5\xF9\x7E\x5A\x10"                             , "vmovd dword ptr [edx+0x10], xmm3"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC5\xF9\xD6\x5A\x10"                             , "vmovq qword ptr [edx+0x10], xmm3"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC5\xF9\x6E\xEB"                                 , "vmovd xmm5, ebx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC5\xF9\x7E\xEB"                                 , "vmovd ebx, xmm5"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC5\xFA\x7E\xC1"                                 , "vmovq xmm0, xmm1"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\x7D\x08\x6E\xC0"                         , "evex vmovd xmm0, eax"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\x7D\x08\x7E\xC0"                         , "evex vmovd eax, xmm0"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC5\xF5\xFD\xC7"                                 , "vpaddw ymm0, ymm1, ymm7"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC4\xE3\x71\x41\xC2\x00"                         , "vdppd xmm0, xmm1, xmm2, 0"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\xF5\xD9\x58\x00"                         , "vaddpd zmm0 {k1}{z}, zmm1, [eax] {1to8}"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC5\xF0\x58\xC2"                                 , "vaddps xmm0, xmm1, xmm2"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\x74\x88\x58\xC2"                         , "vaddps xmm0 {z}, xmm1, xmm2"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\x74\x89\x58\xC2"                         , "vaddps xmm0 {k1}{z}, xmm1, xmm2"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\x6C\x4F\xC2\x54\x98\x04\x0F"             , "vcmpps k2 {k7}, zmm2, zmmword ptr [eax+ebx*4+256], 15"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\x6C\x5F\xC2\x54\x98\x40\x0F"             , "vcmpps k2 {k7}, zmm2, dword ptr [eax+ebx*4+256] {1to16}, 15"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC5\xFA\x2D\xC1"                                 , "vcvtss2si eax, xmm1"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC5\xFB\x2D\xC1"                                 , "vcvtsd2si eax, xmm1"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC5\xF2\x2A\xC2"                                 , "vcvtsi2ss xmm0, xmm1, edx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC5\xF3\x2A\xC2"                                 , "vcvtsi2sd xmm0, xmm1, edx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC5\xFB\xE6\x3B"                                 , "vcvtpd2dq xmm7, xmmword ptr [ebx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC5\xFF\xE6\x3B"                                 , "vcvtpd2dq xmm7, ymmword ptr [ebx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC5\xF9\x5A\x3B"                                 , "vcvtpd2ps xmm7, xmmword ptr [ebx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC5\xFD\x5A\x3B"                                 , "vcvtpd2ps xmm7, ymmword ptr [ebx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC5\xF9\x5A\xC1"                                 , "vcvtpd2ps xmm0, xmm1"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC5\xF9\x5A\x03"                                 , "vcvtpd2ps xmm0, xmmword ptr [ebx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC5\xFD\x5A\xC1"                                 , "vcvtpd2ps xmm0, ymm1"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC5\xFD\x5A\x03"                                 , "vcvtpd2ps xmm0, ymmword ptr [ebx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\xFD\x48\x5A\xC1"                         , "vcvtpd2ps ymm0, zmm1"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\xFD\x48\x5A\x03"                         , "vcvtpd2ps ymm0, zmmword ptr [ebx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\xFC\x08\x79\x3B"                         , "vcvtpd2udq xmm7, xmmword ptr [ebx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\xFC\x28\x79\x3B"                         , "vcvtpd2udq xmm7, ymmword ptr [ebx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\xFC\x08\x5B\x3B"                         , "vcvtqq2ps xmm7, xmmword ptr [ebx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\xFC\x28\x5B\x3B"                         , "vcvtqq2ps xmm7, ymmword ptr [ebx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC5\xF9\xE6\x3B"                                 , "vcvttpd2dq xmm7, xmmword ptr [ebx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC5\xFD\xE6\x3B"                                 , "vcvttpd2dq xmm7, ymmword ptr [ebx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\xFC\x08\x78\x3B"                         , "vcvttpd2udq xmm7, xmmword ptr [ebx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\xFC\x28\x78\x3B"                         , "vcvttpd2udq xmm7, ymmword ptr [ebx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\xFF\x08\x7A\x3B"                         , "vcvtuqq2ps xmm7, xmmword ptr [ebx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\xFF\x28\x7A\x3B"                         , "vcvtuqq2ps xmm7, ymmword ptr [ebx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x62\xF3\xFD\x08\x66\x3F\x01"                     , "vfpclasspd k7, xmmword ptr [edi], 0x01"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x62\xF3\xFD\x28\x66\x3F\x01"                     , "vfpclasspd k7, ymmword ptr [edi], 0x01"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x62\xF3\xFD\x48\x66\x3F\x01"                     , "vfpclasspd k7, zmmword ptr [edi], 0x01"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x62\xF3\x7D\x08\x66\x3F\x01"                     , "vfpclassps k7, xmmword ptr [edi], 0x01"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x62\xF3\x7D\x28\x66\x3F\x01"                     , "vfpclassps k7, ymmword ptr [edi], 0x01"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x62\xF3\x7D\x48\x66\x3F\x01"                     , "vfpclassps k7, zmmword ptr [edi], 0x01"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC4\xE2\xF9\x90\x04\x05\x00\x00\x00\x00"         , "vpgatherdq xmm0, [xmm0], xmm0"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC4\xE2\xFD\x91\x04\x05\x00\x00\x00\x00"         , "vpgatherqq ymm0, [ymm0], ymm0"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC4\xE2\xE9\x92\x0C\x00"                         , "vgatherdpd xmm1, [eax + xmm0], xmm2"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x62\xF3\x6D\x08\x3E\xCB\x00"                     , "vpcmpub k1, xmm2, xmm3, 0x0"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x62\xF2\x6D\x48\xCF\x4C\x11\x01"                 , "vgf2p8mulb zmm1, zmm2, zmmword ptr [ecx+edx+64]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x62\xF3\xED\x48\xCE\x4C\x11\x01\x0F"             , "vgf2p8affineqb zmm1, zmm2, zmmword ptr [ecx+edx+64], 15"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x62\xF3\xED\x48\xCF\x4C\x11\x01\x0F"             , "vgf2p8affineinvqb zmm1, zmm2, zmmword ptr [ecx+edx+64], 15"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x62\xF2\x67\x48\x68\x24\x6D\x00\xF8\xFF\xFF"     , "vp2intersectd k4, k5, zmm3, zmmword ptr [ebp*2 - 2048]"),

  // 64-bit AVX+ and AVX512+ instructions.
  X64_PASS(RELOC_BASE_ADDRESS, "\xC5\xF9\x6E\x5A\x10"                             , "vmovd xmm3, dword ptr [rdx+0x10]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC5\xFA\x7E\x5A\x10"                             , "vmovq xmm3, qword ptr [rdx+0x10]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC5\xF9\x7E\x5A\x10"                             , "vmovd dword ptr [rdx+0x10], xmm3"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC5\xF9\xD6\x5A\x10"                             , "vmovq qword ptr [rdx+0x10], xmm3"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC5\xF9\x6E\xEB"                                 , "vmovd xmm5, ebx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xE1\xF9\x6E\xEB"                             , "vmovq xmm5, rbx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\x61\x7D\x08\x6E\xFB"                         , "vmovd xmm31, ebx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\x61\xFD\x08\x6E\xFB"                         , "vmovq xmm31, rbx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC5\xF9\x7E\xEB"                                 , "vmovd ebx, xmm5"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xE1\xF9\x7E\xEB"                             , "vmovq rbx, xmm5"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\x61\x7D\x08\x7E\xFB"                         , "vmovd ebx, xmm31"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\x61\xFD\x08\x7E\xFB"                         , "vmovq rbx, xmm31"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC5\xFA\x7E\xC1"                                 , "vmovq xmm0, xmm1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\x7D\x08\x6E\xC0"                         , "evex vmovd xmm0, eax"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\xFD\x08\x6E\xC0"                         , "evex vmovq xmm0, rax"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\x7D\x08\x7E\xC0"                         , "evex vmovd eax, xmm0"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\xFD\x08\x7E\xC0"                         , "evex vmovq rax, xmm0"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\x41\x35\xFD\xC7"                             , "vpaddw ymm8, ymm9, ymm15"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\x43\x21\x41\xD4\x00"                         , "vdppd xmm10, xmm11, xmm12, 0"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\x71\xB5\xD9\x58\x08"                         , "vaddpd zmm9 {k1}{z}, zmm9, [rax] {1to8}"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC5\xF0\x58\xC2"                                 , "vaddps xmm0, xmm1, xmm2"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\x74\x88\x58\xC2"                         , "vaddps xmm0 {z}, xmm1, xmm2"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC5\xFA\x2D\xC1"                                 , "vcvtss2si eax, xmm1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xE1\xFA\x2D\xC1"                             , "vcvtss2si rax, xmm1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC5\xFB\x2D\xC1"                                 , "vcvtsd2si eax, xmm1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xE1\xFB\x2D\xC1"                             , "vcvtsd2si rax, xmm1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC5\xF2\x2A\xC2"                                 , "vcvtsi2ss xmm0, xmm1, edx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xE1\xF2\x2A\xC2"                             , "vcvtsi2ss xmm0, xmm1, rdx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC5\xF3\x2A\xC2"                                 , "vcvtsi2sd xmm0, xmm1, edx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xE1\xF3\x2A\xC2"                             , "vcvtsi2sd xmm0, xmm1, rdx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC5\x7B\xE6\x3B"                                 , "vcvtpd2dq xmm15, xmmword ptr [rbx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC5\x7F\xE6\x3B"                                 , "vcvtpd2dq xmm15, ymmword ptr [rbx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC5\x79\x5A\x3B"                                 , "vcvtpd2ps xmm15, xmmword ptr [rbx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC5\x7D\x5A\x3B"                                 , "vcvtpd2ps xmm15, ymmword ptr [rbx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\x71\xFC\x08\x79\x3B"                         , "vcvtpd2udq xmm15, xmmword ptr [rbx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\x71\xFC\x28\x79\x3B"                         , "vcvtpd2udq xmm15, ymmword ptr [rbx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\x71\xFC\x08\x5B\x3B"                         , "vcvtqq2ps xmm15, xmmword ptr [rbx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\x71\xFC\x28\x5B\x3B"                         , "vcvtqq2ps xmm15, ymmword ptr [rbx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC5\xF9\x5A\xC1"                                 , "vcvtpd2ps xmm0, xmm1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC5\xF9\x5A\x03"                                 , "vcvtpd2ps xmm0, xmmword ptr [rbx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC5\xFD\x5A\xC1"                                 , "vcvtpd2ps xmm0, ymm1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC5\xFD\x5A\x03"                                 , "vcvtpd2ps xmm0, ymmword ptr [rbx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\xFD\x48\x5A\xC1"                         , "vcvtpd2ps ymm0, zmm1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\xFD\x48\x5A\x03"                         , "vcvtpd2ps ymm0, zmmword ptr [rbx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC5\x79\xE6\x3B"                                 , "vcvttpd2dq xmm15, xmmword ptr [rbx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC5\x7D\xE6\x3B"                                 , "vcvttpd2dq xmm15, ymmword ptr [rbx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\x71\xFC\x08\x78\x3B"                         , "vcvttpd2udq xmm15, xmmword ptr [rbx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\x71\xFC\x28\x78\x3B"                         , "vcvttpd2udq xmm15, ymmword ptr [rbx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\x71\xFF\x08\x7A\x3B"                         , "vcvtuqq2ps xmm15, xmmword ptr [rbx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\x71\xFF\x28\x7A\x3B"                         , "vcvtuqq2ps xmm15, ymmword ptr [rbx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF3\xFD\x08\x66\x3F\x01"                     , "vfpclasspd k7, xmmword ptr [rdi], 0x01"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF3\xFD\x28\x66\x37\x01"                     , "vfpclasspd k6, ymmword ptr [rdi], 0x01"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF3\xFD\x48\x66\x2F\x01"                     , "vfpclasspd k5, zmmword ptr [rdi], 0x01"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF3\x7D\x08\x66\x27\x01"                     , "vfpclassps k4, xmmword ptr [rdi], 0x01"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF3\x7D\x28\x66\x1F\x01"                     , "vfpclassps k3, ymmword ptr [rdi], 0x01"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF3\x7D\x48\x66\x17\x01"                     , "vfpclassps k2, zmmword ptr [rdi], 0x01"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\x01\x95\x10\x58\xF4"                         , "vaddpd zmm30, zmm29, zmm28  {rn-sae}"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\x01\x95\x10\x58\xF4"                         , "vaddpd zmm30, zmm29, zmm28, {rn-sae}"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\x01\x95\x30\x58\xF4"                         , "vaddpd zmm30, zmm29, zmm28  {rd-sae}"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\x01\x95\x30\x58\xF4"                         , "vaddpd zmm30, zmm29, zmm28, {rd-sae}"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\x01\x95\x50\x58\xF4"                         , "vaddpd zmm30, zmm29, zmm28  {ru-sae}"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\x01\x95\x50\x58\xF4"                         , "vaddpd zmm30, zmm29, zmm28, {ru-sae}"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\x01\x95\x70\x58\xF4"                         , "vaddpd zmm30, zmm29, zmm28  {rz-sae}"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\x01\x95\x70\x58\xF4"                         , "vaddpd zmm30, zmm29, zmm28, {rz-sae}"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\x6C\x4F\xC2\x54\x98\x04\x0F"             , "vcmpps k2 {k7}, zmm2, zmmword ptr [rax+rbx*4+256], 15"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\x6C\x1F\xC2\x54\x98\x40\x0F"             , "vcmpps k2 {k7}, xmm2, dword ptr [rax+rbx*4+256] {1to4}, 15"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\x6C\x3F\xC2\x54\x98\x40\x0F"             , "vcmpps k2 {k7}, ymm2, dword ptr [rax+rbx*4+256] {1to8}, 15"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\x6C\x5F\xC2\x54\x98\x40\x0F"             , "vcmpps k2 {k7}, zmm2, dword ptr [rax+rbx*4+256] {1to16}, 15"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\xFD\x18\xC2\xC1\x00"                     , "vcmppd k0, zmm0, zmm1, 0x00, {sae}"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\x01\xFD\x18\x2E\xF5"                         , "vucomisd xmm30, xmm29  {sae}"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\x01\xFD\x18\x2E\xF5"                         , "vucomisd xmm30, xmm29, {sae}"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\x01\x7C\x18\x2E\xF5"                         , "vucomiss xmm30, xmm29  {sae}"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\x01\x7C\x18\x2E\xF5"                         , "vucomiss xmm30, xmm29, {sae}"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xE2\xFD\x91\x04\x05\x00\x00\x00\x00"         , "vpgatherqq ymm0, [ymm0], ymm0"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xE2\xE9\x92\x0C\x00"                         , "vgatherdpd xmm1, [rax + xmm0], xmm2"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xE2\x69\x90\x44\x0D\x00"                     , "vpgatherdd xmm0, [rbp + xmm1], xmm2"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xC2\x69\x90\x04\x0C"                         , "vpgatherdd xmm0, [r12 + xmm1], xmm2"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xC2\x69\x90\x44\x0D\x00"                     , "vpgatherdd xmm0, [r13 + xmm1], xmm2"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF3\x6D\x08\x3E\xCB\x00"                     , "vpcmpub k1, xmm2, xmm3, 0x0"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC5\xE9\xFE\x4C\x11\x40"                         , "vpaddd xmm1, xmm2, [rcx+rdx+64]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC5\xED\xFE\x4C\x11\x40"                         , "vpaddd ymm1, ymm2, [rcx+rdx+64]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF1\x6D\x48\xFE\x4C\x11\x01"                 , "vpaddd zmm1, zmm2, [rcx+rdx+64]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xE2\x3D\x08\x50\x44\x11\x04"                 , "vpdpbusd xmm16, xmm8, [rcx+rdx+64]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xE2\x3D\x28\x50\x44\x11\x02"                 , "vpdpbusd ymm16, ymm8, [rcx+rdx+64]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xE2\x3D\x48\x50\x44\x11\x01"                 , "vpdpbusd zmm16, zmm8, [rcx+rdx+64]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF2\x6D\x48\xCF\x4C\x11\x01"                 , "vgf2p8mulb zmm1, zmm2, zmmword ptr [rcx+rdx+64]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF3\xED\x48\xCE\x4C\x11\x01\x0F"             , "vgf2p8affineqb zmm1, zmm2, zmmword ptr [rcx+rdx+64], 15"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF3\xED\x48\xCF\x4C\x11\x01\x0F"             , "vgf2p8affineinvqb zmm1, zmm2, zmmword ptr [rcx+rdx+64], 15"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF2\x7D\x08\x7A\xC6"                         , "vpbroadcastb xmm0, esi"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF2\x7D\x28\x7A\xC6"                         , "vpbroadcastb ymm0, esi"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF2\x7D\x48\x7A\xC6"                         , "vpbroadcastb zmm0, esi"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF2\xCD\x08\x8D\xF8"                         , "vpermw xmm7, xmm6, xmm0"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xE3\xFD\x01\xFE\x01"                         , "vpermpd ymm7, ymm6, 1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF3\xFD\x48\x01\xFE\x01"                     , "vpermpd zmm7, zmm6, 1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF2\xCD\x28\x16\xF8"                         , "vpermpd ymm7, ymm6, ymm0"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF2\xCD\x48\x16\xF8"                         , "vpermpd zmm7, zmm6, zmm0"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xE2\x4D\x16\xF9"                             , "vpermps ymm7, ymm6, ymm1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF2\x4D\x48\x16\xF9"                         , "vpermps zmm7, zmm6, zmm1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\x92\x47\x20\x68\xF0"                         , "vp2intersectd k6, k7, ymm23, ymm24"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xB2\x47\x20\x68\xB4\xF5\x00\x00\x00\x10"     , "vp2intersectd k6, k7, ymm23, [rbp + r14*8 + 268435456]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF2\x47\x30\x68\x35\x00\x00\x00\x00"         , "vp2intersectd k6, k7, ymm23, dword ptr [rip]{1to8}"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF2\x47\x20\x68\x34\x6D\x00\xFC\xFF\xFF"     , "vp2intersectd k6, k7, ymm23, ymmword ptr [rbp*2 - 1024]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x62\xF2\x47\x20\x68\x71\x7F"                     , "vp2intersectd k6, k7, ymm23, ymmword ptr [rcx + 4064]"),

  // 32-bit jmp/call/ret.
  X86_PASS(0x0000000077513BEE, "\xEB\xFE"                                         , "JMP SHORT 0x77513BEE"),
  X86_PASS(0x0000000077513BEE, "\xEB\x07"                                         , "JMP SHORT 0x77513BF7"),
  X86_PASS(0x0000000077513BEE, "\xEB\xCF"                                         , "JMP SHORT 0x77513BBF"),
  X86_PASS(0x0000000000405C5B, "\xE9\xCA\x70\x00\x00"                             , "JMP 0x0040CD2A"),
  X86_PASS(0x0000000000405C5B, "\xE9\x40\xFE\xFF\xFF"                             , "JMP 0x00405AA0"),
  X86_PASS(0x0000000000405C5B, "\xFF\x25\x00\x01\x00\x00"                         , "JMP DWORD PTR DS:[0x100]"),
  X86_PASS(0x0000000000405C5B, "\xE8\xCA\x70\x00\x00"                             , "CALL 0x0040CD2A"),
  X86_PASS(0x0000000000405EF0, "\xE8\x06\xFF\xFF\xFF"                             , "CALL 0x00405DFB"),
  X86_PASS(0x0000000000405CCC, "\xFF\x15\x10\x00\x00\x00"                         , "CALL DWORD PTR DS:[0x10]"),
  X86_PASS(0x0000000000405C5B, "\xF2\xE9\xC9\x70\x00\x00"                         , "bnd jmp 0x0040CD2A"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC3"                                             , "ret"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC2\x10\x00"                                     , "ret 16"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\xC3"                                         , "rep ret"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF2\xC3"                                         , "bnd ret"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF2\xC3"                                         , "repne ret"),

  // 64-bit jmp/call/ret.
  X64_PASS(0x00007FFCAA022104, "\xEB\xFE"                                         , "JMP SHORT 0x7FFCAA022104"),
  X64_PASS(0x00007FFCAA022104, "\xEB\x22"                                         , "JMP SHORT 0x7FFCAA022128"),
  X64_PASS(0x00007FFCAA022104, "\xEB\xF9"                                         , "JMP SHORT 0x7FFCAA0220FF"),
  X64_PASS(0x00007FFCA9FF197C, "\xE9\x35\x64\x93\x53"                             , "JMP 0x7FFCFD927DB6"),
  X64_PASS(0x00007FFCAA022104, "\xE9\x7C\xF4\xFC\xFF"                             , "JMP 0x7FFCA9FF1585"),
  X64_PASS(0x0000000123456789, "\xFF\x25\xFA\xFF\xFF\xFF"                         , "JMP QWORD[0x123456789]"),
  X64_PASS(0x00007FFCA9FF1977, "\xFF\x25\xFA\x00\xFF\xFF"                         , "JMP QWORD PTR DS:[0x7FFCA9FE1A77]"),
  X64_PASS(0x00007FFCA9FF197C, "\xF2\xE9\x34\x64\x93\x53"                         , "bnd jmp 0x7FFCFD927DB6"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC3"                                             , "ret"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC2\x10\x00"                                     , "ret 16"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\xC3"                                         , "rep ret"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF2\xC3"                                         , "bnd ret"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF2\xC3"                                         , "repne ret"),

  // 32-bit miscellaneous instructions.
  X86_PASS(0x0000000000405C6A, "\xFF\x35\xF4\x0A\x47\x00"                         , "PUSH DWORD PTR DS:[0x00000000470AF4]"),
  X86_PASS(0x0000000000405C92, "\x8B\x45\x08"                                     , "MOV EAX,DWORD PTR SS:[EBP+8]"),
  X86_PASS(0x0000000000405CB8, "\xC7\x45\xF4\x00\x40\x99\x01"                     , "MOV DWORD PTR SS:[EBP-0x00000000C],0x000000001994000"),
  X86_PASS(0x0000000000405D4C, "\x8A\x14\x08"                                     , "MOV DL,BYTE PTR DS:[EAX+ECX]"),
  X86_PASS(0x0000000000405D4C, "\x0F\xB7\x4C\x45\x98"                             , "MOVZX ECX,WORD PTR SS:[EAX*2+EBP-0x0000000068]"),
  X86_PASS(0x0000000000405D4C, "\xC6\x84\x30\x1D\x01\x00\x00\x00"                 , "MOV BYTE PTR DS:[EAX+ESI+0x0000000011D],0"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x6A\x0D"                                         , "PUSH 0x00000000D"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x68\xFF\x00\x00\x00"                             , "PUSH 0x00000000FF"),
  X86_PASS(0x0000000000405FF9, "\x83\x60\x70\xFD"                                 , "AND DWORD PTR DS:[EAX+0x0000000070],0x00000000FFFFFFFD"),
  X86_PASS(0x0000000000405FF9, "\x81\x60\x70\x0D\x00\x00\xF0"                     , "AND DWORD PTR DS:[EAX+0x0000000070],0x00000000F000000D"),
  X86_PASS(0x0000000000405C23, "\xf2\x0f\x11\x0d\x00\x00\x00\x00"                 , "MOVSD QWORD PTR ds:[0x000000000],xmm1"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x8B\x04\xCD\x00\x00\x00\x00"                     , "MOV EAX,[ECX*8]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x60"                                             , "PUSHAD"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xCC"                                             , "INT3"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xCD\x03"                                         , "INT 3"),
  X86_PASS(0x0000000000405C23, "\xE7\xE9"                                         , "OUT 0x00000000E9, EAX"),
  X86_PASS(0x0000000000405C23, "\x69\xC0\xFF\x01\x00\x00"                         , "IMUL EAX, EAX, 0x000000001FF"),
  X86_PASS(0x0000000000405C23, "\x69\xC0\xFF\x00\x00\x00"                         , "IMUL EAX, EAX, 0x00000000FF"),
  X86_PASS(0x0000000000405C23, "\x69\xC0\xFE\x00\x00\x00"                         , "IMUL EAX, EAX, 0x00000000FE"),
  X86_PASS(0x0000000000405C23, "\x6B\xC0\x1E"                                     , "IMUL EAX, EAX, 0x000000001E"),
  X86_PASS(0x0000000000405C23, "\xB8\x78\x56\x34\x12"                             , "MOV EAX, 0x0000000012345678"),
  X86_PASS(0x0000000000405C23, "\xB8\xFE\xFF\xFF\xFF"                             , "MOV EAX, 0x00000000FFFFFFFE"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xDF\x3C\x24"                                     , "FISTP QWORD PTR [ESP]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xD9\xF6"                                         , "FDECSTP"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xD9\xFF"                                         , "FCOS"),
  X86_PASS(0x0000000000405C23, "\xC7\x85\xE8\xFD\xFF\xFF\x00\x00\x08\x02"         , "MOV DWORD PTR [EBP-0x00000000218],0x000000002080000"),
  X86_PASS(0x0000000000405C23, "\xC7\x84\x24\xE8\xFD\xFF\xFF\x00\x00\x08\x02"     , "MOV DWORD PTR [ESP-0x00000000218],0x000000002080000"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC7\x05\xBA\x55\x0F\x00\xFF\x00\x00\x00"         , "MOV DWORD PTR [0x00000000F55BA], 0x00000000FF"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\xC7\x05\xBA\x55\x0F\x00\xFF\x00"             , "MOV WORD PTR [0x00000000F55BA], 0x00000000FF"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xC6\x05\xBA\x55\x0F\x00\xFF"                     , "MOV BYTE PTR [0x00000000F55BA], 0x00000000FF"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x81\x38\x80\x07\x00\x00"                         , "CMP DWORD PTR [EAX], 0x00000000780"),

  // 64-bit miscellaneous instructions.
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\xB8\x90\x78\x56\x34\x12\x00\x00\x00"         , "MOV RAX, 0x1234567890"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\xC7\xC0\x00\x00\x00\x00"                     , "MOV RAX, 0"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\xB8\x00\x00\x00\x00\x01\x00\x00\x00"         , "MOV RAX, 0x0000100000000"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\xC7\xC0\x8F\xFA\xFF\x00"                     , "MOV RAX, 0x0000FFFA8F"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\xB8\x90\x78\x56\x34\x12\x00\x00\x00"         , "MOVABS RAX, 0x00001234567890"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\xB8\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF"         , "MOVABS RAX, 0x0000FFFFFFFFFFFFFFFE"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x49\xB8\xF8\xFF\xFF\xFF\x01\x00\x00\x00"         , "movabs r8,0x1fffffff8"),
  X64_PASS(0x00007FFCA9FF1977, "\x48\xA1\x90\x78\x56\x34\x12\x00\x00\x00"         , "MOV RAX, QWORD PTR DS:[0x00001234567890]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xCC"                                             , "INT3"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xCD\x03"                                         , "INT 3"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\x63\xD0"                                     , "MOVSXD RDX, EAX"),
  X64_PASS(0x00007FFCA9FF1977, "\x45\x0F\xBE\x24\x2F"                             , "MOVSX R12D, BYTE PTR [R15+RBP*1]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x4D\x69\xED\x10\x01\x00\x00"                     , "IMUL R13, R13, 0x0000110"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x4D\x6B\xED\x11"                                 , "IMUL R13, R13, 0x000011"),
  X64_PASS(0x00007FFCA9FF1977, "\x48\xC7\x05\xAF\x55\x0F\x00\xFF\x00\x00\x00"     , "MOV QWORD PTR [RIP+0x0000F55AF], 0x0000FF"),
  X64_PASS(0x0000000000000000, "\x48\xC7\x05\xAF\x55\x0F\x00\xFF\x00\x00\x00"     , "MOV QWORD PTR [0x0000F55BA], 0x0000FF"),
  X64_PASS(0x00007FFCA9FF1977, "\x48\xC7\x05\xAF\x55\x0F\x00\xFE\xFF\xFF\xFF"     , "MOV QWORD PTR [RIP+0x0000F55AF], 0x0000FFFFFFFFFFFFFFFE"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\xC7\x08"                                     , "CMPXCHG8B [RAX]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\x0F\xC7\x08"                                 , "CMPXCHG16B [RAX]"),
  X64_PASS(0x00007FF6845CB974, "\x48\x8D\x15\xA5\x16\x25\x00"                     , "LEA RDX, QWORD PTR DS:[0x00007FF68481D020]"),
  X64_PASS(0x00007FF6845CB974, "\x48\x8D\x15\xA5\x16\x25\x00"                     , "LEA RDX, QWORD PTR DS:[RIP+0x00002516A5]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\x8D\x10"                                     , "LEA RDX, [RAX]"),
  X64_PASS(0x00007FF6845CB982, "\x48\x83\x05\x63\x0F\x25\x00\x01"                 , "ADD QWORD PTR [0x00007FF68481C8ED], 0x00001"),
  X64_PASS(0x00007FF6845CB982, "\x48\x83\x05\x63\x0F\x25\x00\x01"                 , "ADD QWORD PTR [RIP+0x0000250F63], 0x00001"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x48\x83\x05\xFF\xFF\xFF\xFF\x01"                 , "ADD QWORD PTR [RIP+0x0000FFFFFFFF], 0x00001"),
  X64_PASS(0x00007FFB65E2199E, "\x48\x83\x05\xFF\xFF\xFF\xFF\x48"                 , "ADD QWORD PTR [0x00007FFB65E219A5], 0x000048"),
  X64_PASS(0x000007FEF18BC878, "\xC7\x05\x5E\x3B\xD8\xFF\x00\x00\x00\x00"         , "MOV DWORD PTR DS:[0x00007FEF16403E0],0"),
  X64_PASS(0x0000000000000000, "\x66\xC7\x05\x4B\xFF\x0F\x00\x00\x00"             , "MOV WORD PTR DS:[0x0000FFF54],0"),
  X64_PASS(0x0000000000000000, "\xC6\x05\x4D\xFF\x0F\x00\x00"                     , "MOV BYTE PTR DS:[0x0000FFF54],0"),

  // 32-bit instruction aliases.
  X86_PASS(0x000000000040652A, "\xC0\x64\x18\x50\xFF"                             , "SAL BYTE PTR DS:[EAX+EBX+0x0000000050],0x00000000FF"),

  // 32-bit string instructions.
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x67\x6C"                                     , "rep   insb  byte  ptr es:[di], dx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x67\x6D"                                     , "rep   insd  dword ptr es:[di], dx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x67\x6E"                                     , "rep   outsb dx, byte  ptr [si]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x67\x6F"                                     , "rep   outsd dx, dword ptr [si]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x67\xA4"                                     , "rep   movsb byte  ptr es:[di], byte  ptr [si]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x67\xA5"                                     , "rep   movsd dword ptr es:[di], dword ptr [si]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x67\xA6"                                     , "repe  cmpsb byte  ptr [si], byte  ptr es:[di]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x67\xA7"                                     , "repe  cmpsd dword ptr [si], dword ptr es:[di]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x67\xAA"                                     , "rep   stosb byte  ptr es:[di], al"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x67\xAB"                                     , "rep   stosd dword ptr es:[di], eax"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x67\xAC"                                     , "rep   lodsb al , byte  ptr [si]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x67\xAD"                                     , "rep   lodsd eax, dword ptr [si]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x67\xAE"                                     , "repe  scasb al , byte  ptr es:[di]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x67\xAF"                                     , "repe  scasd eax, dword ptr es:[di]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF2\x6C"                                         , "repne insb  byte ptr es:[edi], dx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF2\x66\x6D"                                     , "repne insw  word ptr es:[edi], dx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF2\x6E"                                         , "repne outsb dx, byte ptr [esi]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF2\x66\x6F"                                     , "repne outsw dx, word ptr [esi]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF2\xA4"                                         , "repne movsb byte ptr es:[edi], byte ptr [esi]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF2\x66\xA5"                                     , "repne movsw word ptr es:[edi], word ptr [esi]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF2\xA6"                                         , "repne cmpsb byte ptr [esi], byte ptr es:[edi]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF2\x66\xA7"                                     , "repne cmpsw word ptr [esi], word ptr es:[edi]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF2\xAA"                                         , "repne stosb byte ptr es:[edi], al"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF2\x66\xAB"                                     , "repne stosw word ptr es:[edi], ax"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF2\xAC"                                         , "repne lodsb al, byte ptr [esi]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF2\x66\xAD"                                     , "repne lodsw ax, word ptr [esi]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF2\xAE"                                         , "repne scasb al, byte ptr es:[edi]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF2\x66\xAF"                                     , "repne scasw ax, word ptr es:[edi]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x67\x6C"                                     , "rep   insb  byte ptr es:[di], dx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x66\x67\x6D"                                 , "rep   insw  word ptr es:[di], dx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x67\x6E"                                     , "rep   outsb dx, byte ptr [si]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x66\x67\x6F"                                 , "rep   outsw dx, word ptr [si]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x67\xA4"                                     , "rep   movsb byte ptr es:[di], byte ptr [si]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x66\x67\xA5"                                 , "rep   movsw word ptr es:[di], word ptr [si]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x67\xA6"                                     , "repe  cmpsb byte ptr [si], byte ptr es:[di]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x66\x67\xA7"                                 , "repe  cmpsw word ptr [si], word ptr es:[di]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x67\xAA"                                     , "rep   stosb byte ptr es:[di], al"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x66\x67\xAB"                                 , "rep   stosw word ptr es:[di], ax"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x67\xAC"                                     , "rep   lodsb al, byte ptr [si]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x66\x67\xAD"                                 , "rep   lodsw ax, word ptr [si]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x67\xAE"                                     , "repe  scasb al, byte ptr es:[di]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x66\x67\xAF"                                 , "repe  scasw ax, word ptr es:[di]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x6C"                                         , "rep   insb  byte  ptr es:[edi], dx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x6D"                                         , "rep   insd  dword ptr es:[edi], dx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x6E"                                         , "rep   outsb dx, byte  ptr [esi]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x6F"                                         , "rep   outsd dx, dword ptr [esi]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\xA4"                                         , "rep   movsb byte  ptr es:[edi], byte  ptr [esi]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\xA5"                                         , "rep   movsd dword ptr es:[edi], dword ptr [esi]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\xA6"                                         , "repe  cmpsb byte  ptr [esi], byte  ptr es:[edi]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\xA7"                                         , "repe  cmpsd dword ptr [esi], dword ptr es:[edi]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\xAA"                                         , "rep   stosb byte  ptr es:[edi], al"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\xAB"                                         , "rep   stosd dword ptr es:[edi], eax"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\xAC"                                         , "rep   lodsb al , byte  ptr [esi]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\xAD"                                         , "rep   lodsd eax, dword ptr [esi]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\xAE"                                         , "repe  scasb al , byte  ptr es:[edi]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\xAF"                                         , "repe  scasd eax, dword ptr es:[edi]"),

  // 64-bit instructions that use extended low-byte registers.
  X64_PASS(RELOC_BASE_ADDRESS, "\x40\x86\x34\x24"                                 , "xchg [rsp], sil"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x40\x86\x3C\x24"                                 , "xchg [rsp], dil"),

  // 32-bit instructions that use non-standard syntax.
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\x38\xF8\x03"                             , "movdir64b [eax], [ebx]"),

  // 64-bit instructions that use non-standard syntax.
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\x38\xF8\x03"                             , "movdir64b [rax], [rbx]"),

  // 32-bit instructions that use non-standard syntax (failure cases).
  X86_FAIL(RELOC_BASE_ADDRESS, "movdir64b [rax], [rbx]"),
  X86_FAIL(RELOC_BASE_ADDRESS, "movdir64b [eax + 1], [ebx]"),
  X86_FAIL(RELOC_BASE_ADDRESS, "movdir64b [eax + rbx], [ebx]"),

  // 64-bit instructions that use non-standard syntax (failure cases).
  X64_FAIL(RELOC_BASE_ADDRESS, "movdir64b [rax + 1], [rbx]"),
  X64_FAIL(RELOC_BASE_ADDRESS, "movdir64b [rax + rbx], [rbx]"),

  // 32-bit VMX instructions.
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\x38\x80\x03"                             , "invept eax, [ebx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\x38\x81\x03"                             , "invvpid eax, [ebx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xC1"                                     , "vmcall"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\xC7\x32"                                 , "vmclear [edx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xD4"                                     , "vmfunc"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xC2"                                     , "vmlaunch"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\xC7\x33"                                     , "vmptrld [ebx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\xC7\x3B"                                     , "vmptrst [ebx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x78\x18"                                     , "vmread [eax], ebx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xC3"                                     , "vmresume"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x79\x03"                                     , "vmwrite eax, [ebx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\xC7\x33"                                 , "vmxon [ebx]"),

  // 64-bit VMX instructions.
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\x38\x80\x03"                             , "invept rax, [rbx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\x38\x81\x03"                             , "invvpid rax, [rbx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xC1"                                     , "vmcall"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\xC7\x32"                                 , "vmclear [rdx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xD4"                                     , "vmfunc"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xC2"                                     , "vmlaunch"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\xC7\x33"                                     , "vmptrld [rbx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\xC7\x3B"                                     , "vmptrst [rbx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x78\x18"                                     , "vmread [rax], rbx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xC3"                                     , "vmresume"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x79\x03"                                     , "vmwrite rax, [rbx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\xC7\x33"                                 , "vmxon [rbx]"),

  // 32-bit LWP instructions.
  X86_PASS(RELOC_BASE_ADDRESS, "\x8F\xE9\x78\x12\xC2"                             , "llwpcb edx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x8F\xE9\x78\x12\xC9"                             , "slwpcb ecx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x8F\xEA\x78\x12\x03\x04\x03\x02\x01"             , "lwpins eax, [ebx], 0x01020304"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x8F\xEA\x78\x12\x0B\x04\x03\x02\x01"             , "lwpval eax, [ebx], 0x01020304"),

  // 64-bit LWP instructions.
  X64_PASS(RELOC_BASE_ADDRESS, "\x8F\xE9\xF8\x12\xC2"                             , "llwpcb rdx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x8F\xE9\xF8\x12\xC9"                             , "slwpcb rcx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x8F\xEA\xF8\x12\x03\x04\x03\x02\x01"             , "lwpins rax, [rbx], 0x01020304"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x8F\xEA\xF8\x12\x0B\x04\x03\x02\x01"             , "lwpval rax, [rbx], 0x01020304"),

  // 32-bit SVM|SKINIT instructions.
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xDD"                                     , "clgi"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xDF"                                     , "invlpga eax, ecx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xDE"                                     , "skinit eax"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xDC"                                     , "stgi"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xDA"                                     , "vmload eax"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xD9"                                     , "vmmcall"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xD8"                                     , "vmrun eax"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xDB"                                     , "vmsave eax"),

  // 64-bit SVM|SKINIT instructions.
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xDD"                                     , "clgi"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x67\x0F\x01\xDF"                                 , "invlpga eax, ecx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xDF"                                     , "invlpga rax, ecx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xDE"                                     , "skinit eax"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xDC"                                     , "stgi"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xDA"                                     , "vmload rax"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xD9"                                     , "vmmcall"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xD8"                                     , "vmrun rax"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xDB"                                     , "vmsave rax"),

  // 32-bit MONITOR & MWAIT instructions.
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xC8"                                     , "monitor"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xC8"                                     , "monitor [eax], ecx, edx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xFA"                                     , "monitorx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xFA"                                     , "monitorx [eax], ecx, edx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xC9"                                     , "mwait"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xC9"                                     , "mwait eax, ecx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xFB"                                     , "mwaitx"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xFB"                                     , "mwaitx eax, ecx, ebx"),

  // 64-bit MONITOR & MWAIT instructions.
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xC8"                                     , "monitor"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xC8"                                     , "monitor [rax], ecx, edx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xFA"                                     , "monitorx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xFA"                                     , "monitorx [rax], ecx, edx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xC9"                                     , "mwait"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xC9"                                     , "mwait eax, ecx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xFB"                                     , "mwaitx"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xFB"                                     , "mwaitx eax, ecx, ebx"),

  // 32-bit WAITPKG instructions.
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\xAE\xF0"                                 , "umonitor [eax]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\xAE\xF7"                                 , "tpause edi"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\xAE\xF7"                                 , "tpause edi, edx, eax"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF2\x0F\xAE\xF7"                                 , "umwait edi"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF2\x0F\xAE\xF7"                                 , "umwait edi, edx, eax"),

  // 64-bit WAITPKG instructions.
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\xAE\xF0"                                 , "umonitor [rax]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\xAE\xF7"                                 , "tpause edi"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\xAE\xF7"                                 , "tpause edi, edx, eax"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF2\x0F\xAE\xF7"                                 , "umwait edi"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF2\x0F\xAE\xF7"                                 , "umwait edi, edx, eax"),

  // 32-bit ENQCMD instructions.
  X86_PASS(RELOC_BASE_ADDRESS, "\xF2\x0F\x38\xF8\x01"                             , "enqcmd [eax], [ecx]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\x38\xF8\x01"                             , "enqcmds [eax], [ecx]"),

  // 64-bit ENQCMD instructions.
  X64_PASS(RELOC_BASE_ADDRESS, "\xF2\x0F\x38\xF8\x01"                             , "enqcmd [rax], [rcx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\x38\xF8\x01"                             , "enqcmds [rax], [rcx]"),

  // 32-bit CL... instructions.
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xFC"                                     , "clzero"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\xAE\x7A\x40"                                 , "clflush [edx + 64]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\xAE\x7A\x40"                             , "clflushopt [edx + 64]"),
  X86_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\xAE\x72\x40"                             , "clwb [edx + 64]"),

  // 64-bit CL... instructions.
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xFC"                                     , "clzero"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\xAE\x7A\x40"                                 , "clflush [rdx + 64]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\xAE\x7A\x40"                             , "clflushopt [rdx + 64]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x0F\xAE\x72\x40"                             , "clwb [rdx + 64]"),

  // 32-bit MCOMMIT instruction.
  X86_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\x01\xFA"                                 , "mcommit"),

  // 64-bit MCOMMIT instruction.
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\x01\xFA"                                 , "mcommit"),

  // 32-bit PCONFIG instructions.
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xC5"                                     , "pconfig"),

  // 64-bit PCONFIG instructions.
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xC5"                                     , "pconfig"),

  // 32-bit SERIALIZE instructions.
  X86_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xE8"                                     , "serialize"),

  // 64-bit SERIALIZE instructions.
  X64_PASS(RELOC_BASE_ADDRESS, "\x0F\x01\xE8"                                     , "serialize"),

  // 32-bit TSXLDTRK instructions.
  X86_PASS(RELOC_BASE_ADDRESS, "\xF2\x0F\x01\xE8"                                 , "xsusldtrk"),
  X86_PASS(RELOC_BASE_ADDRESS, "\xF2\x0F\x01\xE9"                                 , "xresldtrk"),

  // 64-bit TSXLDTRK instructions.
  X64_PASS(RELOC_BASE_ADDRESS, "\xF2\x0F\x01\xE8"                                 , "xsusldtrk"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF2\x0F\x01\xE9"                                 , "xresldtrk"),

  // 64-bit CET_SS instructions.
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\xAE\x34\x25\xF0\x1C\xF0\x1C"             , "clrssbsy [485498096]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\xAE\x32"                                 , "clrssbsy [rdx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\xAE\x72\x40"                             , "clrssbsy [rdx + 64]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\x01\xE8"                                 , "setssbsy"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\x01\xEA"                                 , "saveprevssp"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\x41\x0F\x1E\xCD"                             , "rdsspd r13d"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\x49\x0F\x1E\xCF"                             , "rdsspq r15"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\x41\x0F\xAE\xED"                             , "incsspd r13d"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\x49\x0F\xAE\xEF"                             , "incsspq r15"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\x01\x2C\x25\xF0\x1C\xF0\x1C"             , "rstorssp [485498096]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\x01\x2A"                                 , "rstorssp [rdx]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xF3\x0F\x01\x6A\x40"                             , "rstorssp [rdx + 64]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x4C\x0F\x38\xF6\x3C\x25\xF0\x1C\xF0\x1C"         , "wrssq [485498096], r15"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x4C\x0F\x38\xF6\x3A"                             , "wrssq [rdx], r15"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x4C\x0F\x38\xF5\x3C\x25\xF0\x1C\xF0\x1C"     , "wrussq [485498096], r15"),
  X64_PASS(RELOC_BASE_ADDRESS, "\x66\x4C\x0F\x38\xF5\x3A"                         , "wrussq [rdx], r15"),

  // 64-bit AMX instructions.
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xE2\x78\x49\x00"                             , "ldtilecfg [rax]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xA2\x78\x49\x84\xF5\x00\x00\x00\x10"         , "ldtilecfg [rbp + r14*8 + 268435456]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xC2\x78\x49\x84\x80\x23\x01\x00\x00"         , "ldtilecfg [r8 + rax*4 + 291]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xE2\x78\x49\x05\x00\x00\x00\x00"             , "ldtilecfg [rip]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xE2\x79\x49\x00"                             , "sttilecfg [rax]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xA2\x79\x49\x84\xF5\x00\x00\x00\x10"         , "sttilecfg [rbp + r14*8 + 268435456]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xC2\x79\x49\x84\x80\x23\x01\x00\x00"         , "sttilecfg [r8 + rax*4 + 291]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xE2\x7B\x4B\x0C\x88"                         , "tileloadd tmm1, [rax + rcx*4]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\x82\x7B\x4B\x4C\x08\x01"                     , "tileloadd tmm1, [r8 + r9 + 1]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xA2\x7B\x4B\xB4\xF5\x00\x00\x00\x10"         , "tileloadd tmm6, [rbp + r14*8 + 268435456]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xC2\x7B\x4B\x9C\x80\x23\x01\x00\x00"         , "tileloadd tmm3, [r8 + rax*4 + 291]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xE2\x7B\x4B\x1C\x6D\xE0\xFF\xFF\xFF"         , "tileloadd tmm3, [rbp*2 - 32]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xE2\x7B\x4B\x64\x23\x40"                     , "tileloadd tmm4, [rbx + 64]"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xA2\x7A\x4B\xB4\xF5\x00\x00\x00\x10"         , "tilestored [rbp + r14*8 + 268435456], tmm6"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xE2\x7b\x49\xd8"                             , "tilezero tmm3"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xE2\x7b\x49\xf0"                             , "tilezero tmm6"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xE2\x6A\x5C\xC1"                             , "tdpbf16ps tmm0, tmm1, tmm2"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xE2\x72\x5C\xDA"                             , "tdpbf16ps tmm3, tmm2, tmm1"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xE2\x5A\x5C\xF5"                             , "tdpbf16ps tmm6, tmm5, tmm4"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xE2\x6B\x5E\xC1"                             , "tdpbssd tmm0, tmm1, tmm2"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xE2\x6A\x5E\xC1"                             , "tdpbsud tmm0, tmm1, tmm2"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xE2\x69\x5E\xC1"                             , "tdpbusd tmm0, tmm1, tmm2"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xE2\x68\x5E\xC1"                             , "tdpbuud tmm0, tmm1, tmm2"),
  X64_PASS(RELOC_BASE_ADDRESS, "\xC4\xE2\x78\x49\xC0"                             , "tilerelease"),

  // 32-bit malformed input - should cause either parsing or validation error.
  X86_FAIL(0x0000000000001000, "short jmp 0x2000"),
  X86_FAIL(RELOC_BASE_ADDRESS, "mov al,-129"),
  X86_FAIL(RELOC_BASE_ADDRESS, "mov al, 256"),
  X86_FAIL(RELOC_BASE_ADDRESS, "mov ax,-32769"),
  X86_FAIL(RELOC_BASE_ADDRESS, "mov ax, 65536"),
  X86_FAIL(RELOC_BASE_ADDRESS, "mov eax,-2147483649"),
  X86_FAIL(RELOC_BASE_ADDRESS, "mov eax, 4294967296"),
  X86_FAIL(RELOC_BASE_ADDRESS, "mov rax, 0x0"),
  X86_FAIL(RELOC_BASE_ADDRESS, "mov r15d, 0x0"),
  X86_FAIL(RELOC_BASE_ADDRESS, "mov r15w, 0x0"),
  X86_FAIL(RELOC_BASE_ADDRESS, "mov r15b, 0x0"),
  X86_FAIL(RELOC_BASE_ADDRESS, "mov [eax], 1"),
  X86_FAIL(RELOC_BASE_ADDRESS, "movzx eax, bpl"),
  X86_FAIL(RELOC_BASE_ADDRESS, "shr eax, 256"),
  X64_FAIL(RELOC_BASE_ADDRESS, "lfs al, [ecx]"),
  X86_FAIL(RELOC_BASE_ADDRESS, "MOV EAX, DWORD PTR ]["),
  X86_FAIL(RELOC_BASE_ADDRESS, "MOV EAX, DWORD PTR [RAX]"),
  X86_FAIL(RELOC_BASE_ADDRESS, "MOV EAX, DWORD PTR [0xFFFFFFFFF]"),
  X86_FAIL(RELOC_BASE_ADDRESS, "lock add eax, ecx"),
  X86_FAIL(RELOC_BASE_ADDRESS, "lock add eax, [ecx]"),
  X86_FAIL(RELOC_BASE_ADDRESS, "lock movd mm0, eax"),
  X86_FAIL(RELOC_BASE_ADDRESS, "lock lock add [eax], ecx"),
  X86_FAIL(RELOC_BASE_ADDRESS, "xacquire add [eax], ecx"),
  X86_FAIL(RELOC_BASE_ADDRESS, "xrelease add [eax], ecx"),
  X86_FAIL(RELOC_BASE_ADDRESS, "lock xacquire xrelease add [eax], ecx"),
  X86_FAIL(RELOC_BASE_ADDRESS, "vaddps xmm0 {k0}, xmm1, xmm2"),
  X86_FAIL(RELOC_BASE_ADDRESS, "vaddps xmm0 {k0}{z}, xmm1, xmm2"),

  // 64-bit malformed input - should cause either parsing or validation error.
  X64_FAIL(0x0000000000001000, "short jmp 0x2000"),
  X64_FAIL(RELOC_BASE_ADDRESS, "mov al,-129"),
  X64_FAIL(RELOC_BASE_ADDRESS, "mov al, 256"),
  X64_FAIL(RELOC_BASE_ADDRESS, "mov ax,-32769"),
  X64_FAIL(RELOC_BASE_ADDRESS, "mov ax, 65536"),
  X64_FAIL(RELOC_BASE_ADDRESS, "mov eax,-2147483649"),
  X64_FAIL(RELOC_BASE_ADDRESS, "mov eax, 4294967296"),
  X64_FAIL(RELOC_BASE_ADDRESS, "mov [rax], 1"),
  X64_FAIL(RELOC_BASE_ADDRESS, "movzx r15d, ah"),
  X64_FAIL(RELOC_BASE_ADDRESS, "neg [eax]"),
  X64_FAIL(RELOC_BASE_ADDRESS, "rex neg ah"),
  X64_FAIL(RELOC_BASE_ADDRESS, "shr eax, 256"),
  X64_FAIL(RELOC_BASE_ADDRESS, "shr rax, 256"),
  X64_FAIL(RELOC_BASE_ADDRESS, "lfs al, [rcx]"),
  X64_FAIL(RELOC_BASE_ADDRESS, "lock add rax, rcx"),
  X64_FAIL(RELOC_BASE_ADDRESS, "lock add rax, [rcx]"),
  X64_FAIL(RELOC_BASE_ADDRESS, "lock movd mm0, eax"),
  X64_FAIL(RELOC_BASE_ADDRESS, "lock lock add [rax], rcx"),
  X64_FAIL(RELOC_BASE_ADDRESS, "xacquire add [rax], rcx"),
  X64_FAIL(RELOC_BASE_ADDRESS, "xrelease add [rax], rcx"),
  X64_FAIL(RELOC_BASE_ADDRESS, "lock xacquire xrelease add [rax], rcx"),
  X64_FAIL(RELOC_BASE_ADDRESS, "vaddps xmm0 {k0}, xmm1, xmm2"),
  X64_FAIL(RELOC_BASE_ADDRESS, "vaddps xmm0 {k0}{z}, xmm1, xmm2"),
  X64_FAIL(RELOC_BASE_ADDRESS, "vpgatherdd xmm0, [rip + xmm1], xmm2")
};

struct TestStats {
  uint32_t passed;
  uint32_t failed;
  uint32_t total;
};

struct TestOptions {
  inline TestOptions() { memset(this, 0, sizeof(*this)); }
  bool onlyFailures;
};

static void dumpHex(const char* s, size_t count) {
  for (size_t i = 0; i < count; i++)
    printf("%02X", unsigned(uint8_t(s[i])));
}

static bool runTests(TestStats& out, const TestOptions& options, const TestEntry* entries, size_t count) {
  out.passed = 0;
  out.failed = 0;
  out.total  = uint32_t(count);

  for (size_t i = 0; i < count; i++) {
    const TestEntry& entry = entries[i];
    const char* arch = entry.arch == Arch::kX86 ? "X86" : "X64";

    // Initialize Environment with the requested architecture.
    Environment environment;
    environment.setArch(entry.arch);

    // Initialize CodeHolder.
    CodeHolder code;
    Error err = code.init(environment, entry.baseAddress);

    if (err) {
      printf("CodeHolder.init(): %s [FAILED]\n", DebugUtils::errorAsString(err));

      out.failed++;
      continue;
    }

    x86::Assembler a(&code);
    err = AsmParser(&a).parse(entry.asmString, entry.asmSize);

    if (err) {
      if (!entry.mustPass) {
        if (!options.onlyFailures) {
          printf(" %s: %-55s -> %s [OK]\n", arch, entry.asmString, DebugUtils::errorAsString(err));
        }
        out.passed++;
      }
      else {
        printf("-%s: %-55s -> %s [FAILED]\n", arch, entry.asmString, DebugUtils::errorAsString(err));
        out.failed++;
      }
    }
    else {
      CodeBuffer& buf = code.sectionById(0)->buffer();

      if (entry.mustPass && buf.size() == entry.mcSize && memcmp(buf.data(), entry.machineCode, entry.mcSize) == 0) {
        if (!options.onlyFailures) {
          printf(" %s: %-55s -> ", arch, entry.asmString);
          dumpHex(reinterpret_cast<const char*>(buf.data()), buf.size());
          printf(" [OK]\n");
        }

        out.passed++;
        continue;
      }
      else {
        printf("-%s: %-55s -> ", arch, entry.asmString);
        dumpHex(reinterpret_cast<const char*>(buf.data()), buf.size());

        if (entry.mustPass) {
          printf(" [FAILED]\n");

          size_t numSpaces = 1 + strlen(arch) + 2 + 55;
          for (size_t j = 0; j < numSpaces; j++) printf(" ");

          printf(" != ");
          dumpHex(entry.machineCode, entry.mcSize);
          printf(" [EXPECTED]\n");
        }
        else {
          printf(" [FAILED] Should have failed\n");
        }

        out.failed++;
      }
    }
  }

  return out.failed == 0;
}

int main(int argc, char* argv[]) {
  CmdLine cmdLine(argc, argv);

  TestStats stats;
  TestOptions options;

  if (cmdLine.hasKey("--only-failures"))
    options.onlyFailures = true;

  bool allPassed = runTests(stats, options, testEntries, ASMJIT_ARRAY_SIZE(testEntries));
  if (allPassed) {
    printf("All %u tests passed!\n", stats.total);
    return 0;
  }
  else {
    printf("Passed: %u out of %u\n", stats.passed, stats.total);
    printf("Failed: %u out of %u\n", stats.failed, stats.total);
    return 1;
  }
}
