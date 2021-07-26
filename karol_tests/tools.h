#pragma once

#include <vector>
#include <string>

#define KEYSIZE 43

typedef std::vector<std::uint8_t> OlmBuffer;

struct MockRandom
{
  MockRandom(std::uint8_t offset = 0)
      : tag(0x01), current(offset) {}
  void operator()(
      std::uint8_t *bytes, std::size_t length)
  {
    while (length > 32)
    {
      bytes[0] = tag;
      std::memset(bytes + 1, current, 31);
      length -= 32;
      bytes += 32;
      current += 1;
    }
    if (length)
    {
      bytes[0] = tag;
      std::memset(bytes + 1, current, length - 1);
      current += 1;
    }
  }
  std::uint8_t tag;
  std::uint8_t current;
};

std::vector<size_t> availableSigns;

void initializeAvailableSigns()
{
  if (availableSigns.size())
  {
    return;
  }
  availableSigns.push_back(32);
  for (int i = 48; i <= 57; ++i)
  {
    availableSigns.push_back(i);
  }
  for (int i = 65; i <= 90; ++i)
  {
    availableSigns.push_back(i);
  }
  for (int i = 97; i <= 122; ++i)
  {
    availableSigns.push_back(i);
  }
}

std::string generateRandomString(size_t size)
{
  initializeAvailableSigns();
  std::string result;
  for (int i = 0; i < size; ++i)
  {
    result.push_back(availableSigns[rand() % (availableSigns.size() - 1)]);
  }
  return result;
}

static size_t messageIndex = 0;

std::string generateRandomMessage(size_t forcedSize = 0)
{
  size_t size = (forcedSize == 0) ? rand() % 30 + 40 : forcedSize;
  return "[message " + std::to_string(messageIndex++) + "] " + generateRandomString(size);
}

unsigned char generateRandomByte()
{
  return (unsigned char)rand() % 256;
}

