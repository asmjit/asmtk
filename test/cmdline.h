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

  const char* getKey(const char* key) const {
    std::size_t keyLen = std::strlen(key);
    std::size_t argLen = 0;

    const char* arg = NULL;
    for (int i = 0; i <= argc; i++) {
      if (i == argc)
        return NULL;

      arg = argv[i];
      argLen = std::strlen(arg);
      if (argLen >= keyLen && std::memcmp(arg, key, keyLen) == 0)
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

#endif // _TEST_CMDLINE_H
