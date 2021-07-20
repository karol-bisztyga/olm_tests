#pragma once

#include <vector>
#include <string>

using namespace std;

#define KEYSIZE 43

typedef std::vector<std::uint8_t> OlmBuffer;

vector<size_t> availableSigns;

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

string generateRandomString(size_t size)
{
  initializeAvailableSigns();
  string result;
  for (int i = 0; i < size; ++i)
  {
    result.push_back(availableSigns[rand() % (availableSigns.size() - 1)]);
  }
  return result;
}

string generateRandomMessage(size_t forcedSize = 0)
{
  static size_t messageIndex = 0;
  size_t size = (forcedSize == 0) ? rand() % 30 + 40 : forcedSize;
  return "[message " + to_string(messageIndex++) + "] " + generateRandomString(size);
}

unsigned char generateRandomByte()
{
  return (unsigned char)rand() % 256;
}

/**
 * fills given buffer with random data
 * receives user id and the operation label to ensure the uniqueness
 * across the system. That means the random buffer cannot be the same for 
 *  the same user and two different operations
 *  two different users for the same operation
 * bufferSize has to be big enough to store the user id and the operation label
 * size of user id is 4 for 32-bit system
 */
void generateRandomBuffer(
    string userId,
    string operationLabel,
    OlmBuffer &buffer,
    size_t bufferSize)
{
  if (bufferSize < sizeof(size_t) + operationLabel.size())
  {
    return;
  }
  buffer.resize(bufferSize);
  size_t userIdAsNumber = (size_t)atoi(userId.c_str());
  size_t i = 0;
  for (i = 0; i < sizeof(size_t); ++i)
  {
    buffer[i] = (userIdAsNumber >> i * 8) & 0xff;
  }
  for (char c : operationLabel)
  {
    buffer[++i] = c;
  }
  while (i++ < bufferSize)
  {
    buffer[i] = generateRandomByte();
  }
}
