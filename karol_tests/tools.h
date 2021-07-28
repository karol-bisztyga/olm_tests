#pragma once

#include <vector>
#include <string>

#define KEYSIZE 43

typedef std::vector<std::uint8_t> OlmBuffer;

struct Keys
{
  OlmBuffer identityKeys; // size = 116
  OlmBuffer oneTimeKeys;  // size = 43 each
};

class Tools
{
  Tools() {}
  std::vector<size_t> availableSigns;

public:
  static size_t messageIndex;
  
  static Tools &getInstance()
  {
    static Tools instance;
    return instance;
  }
  Tools(Tools const &) = delete;
  void operator=(Tools const &) = delete;

  void initializeAvailableSigns();
  std::string generateRandomString(size_t size);
  std::string generateRandomMessage(size_t forcedSize = 0);
  unsigned char generateRandomByte();
  void generateRandomBytes(OlmBuffer &buffer, size_t size);
};
