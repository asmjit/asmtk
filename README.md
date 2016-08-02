AsmTK
-----

Assembler toolkit based on AsmJit.

  * [Official Repository (asmjit/asmtk)](https://github.com/asmjit/asmtk)
  * [Official Blog (asmbits)](https://asmbits.blogspot.com/ncr)
  * [Official Chat (gitter)](https://gitter.im/asmjit/asmjit)
  * [Permissive ZLIB license](./LICENSE.md)

Introduction
------------

AsmTK is a sister project of AsmJit library, which provides concepts that are useful mostly in AOT code-generation.

Disclaimer
----------

This project just started and is not complete. AsmTK at the moment requires asmjit:next branch, which will soon replace asmjit:master.

Features
--------

  * Asm parser that can parse everything that AsmJit provides.
  * Assembles to `CodeGen`, which means that it can generare assembly directly or keep it in abstract form for further processing.
  * More to be added :)

AsmParser Usage Guide
---------------------

Assembler parsing is provided by `AsmParser` class, which emits to `CodeGen`:

```C++
#include <asmtk/asmtk.h>

using namespace asmjit;
using namespace asmtk;

// Used to print binary code as hex.
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

int main(int argc, char* argv[]) {
  // Setup a CodeHolder for X64.
  CodeHolder code(ArchInfo::kIdX64);

  // Attach an assembler to the CodeHolder.
  X86Assembler a(&code);

  // Create AsmParser that will emit to X86Assembler.
  AsmParser p(&a);

  // Parse some assembly.
  Error err = p.parse(
    "mov eax, ebx\n"
    "vaddpd zmm0, zmm1, [eax + 128]\n");

  // Error handling (use asmjit::ErrorHandler for more robust error handling).
  if (err) {
    printf("ERROR: %0.8x (%s)\n", err, DebugUtils::errorAsString(err));
    return 1;
  }

  // If we are done, you must detach the Assembler from CodeHolder or sync
  // it, so its internal state and position is synced with CodeHolder.
  code.sync();

  // Now you can print the code, which is stored in the first section (.text).
  CodeBuffer& buffer = code.getSections()[0]->buffer; // TODO: Make this nicer.
  dumpCode(buffer.data, buffer.length);

  return 0;
}
```

You should check out the test directory to see how AsmTK should be used.

Support
-------

Please consider a donation if you use the project and would like to keep it active in the future.

  * [Donate by PayPal](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=QDRM6SRNG7378&lc=EN;&item_name=asmtk&currency_code=EUR)

Authors & Maintainers
---------------------

  * Petr Kobalicek <kobalicek.petr@gmail.com>
