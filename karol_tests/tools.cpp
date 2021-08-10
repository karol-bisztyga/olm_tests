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
  static std::uniform_int_distribution<int> randomStringUid(
      0, availableSigns.size() - 1);
  std::string result;
  for (int i = 0; i < size; ++i)
  {
    result.push_back(availableSigns[randomStringUid(this->mt)]);
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
  static std::uniform_int_distribution<int> randomByteUid(0, 255);
  return (unsigned char)randomByteUid(this->mt);
}

void Tools::generateRandomBytes(OlmBuffer &buffer, size_t size)
{
  buffer.resize(size);

  for (size_t i = 0; i < size; ++i)
  {
    buffer[i] = generateRandomByte();
  }
}
