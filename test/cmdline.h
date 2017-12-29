#ifndef _TEST_CMDLINE_H
#define _TEST_CMDLINE_H

#include <cstring>

class CmdLine {
public:
  CmdLine(int argc, const char* const* argv)
    : argc(argc),
      argv(argv) {}

  bool hasKey(const char* key) const {
    for (int i = 0; i < argc; i++)
      if (std::strcmp(argv[i], key) == 0)
        return true;
    return false;
  }

  const char* valueOf(const char* key) const {
    std::size_t keySize = std::strlen(key);
    std::size_t argSize = 0;

    const char* arg = NULL;
    for (int i = 0; i <= argc; i++) {
      if (i == argc)
        return NULL;

      arg = argv[i];
      argSize = std::strlen(arg);
      if (argSize >= keySize && std::memcmp(arg, key, keySize) == 0)
        break;
    }

    if (argSize > keySize && arg[keySize] == '=')
      return arg + keySize + 1;
    else
      return arg + keySize;
  }

  int argc;
  const char* const* argv;
};

#endif // _TEST_CMDLINE_H
