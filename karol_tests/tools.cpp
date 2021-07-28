#include "tools.h"

size_t Tools::messageIndex = 0;

void Tools::initializeAvailableSigns()
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

std::string Tools::generateRandomString(size_t size)
{
  initializeAvailableSigns();
  std::string result;
  for (int i = 0; i < size; ++i)
  {
    result.push_back(availableSigns[rand() % (availableSigns.size() - 1)]);
  }
  return result;
}

std::string Tools::generateRandomMessage(size_t forcedSize)
{
  size_t size = (forcedSize == 0) ? rand() % 200 + 20 : forcedSize;
  return "[message " + std::to_string(messageIndex++) + "] " + generateRandomString(size);
}

unsigned char Tools::generateRandomByte()
{
  return (unsigned char)rand() % 256;
}

void Tools::generateRandomBytes(OlmBuffer &buffer, size_t size)
{
  buffer.resize(size);

  for (size_t i = 0; i < size; ++i)
  {
    buffer[i] = generateRandomByte();
  }
}
