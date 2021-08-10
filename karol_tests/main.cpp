#include "olm/olm.h"
#include "olm/pk.h"

#include <iostream>

#include <vector>
#include <tuple>
#include <memory>
#include <cstdlib>

#include "tools.h"
#include "user.h"
#include "persist.h"

void messageTest(User *userA, User *userB)
{
  std::cout << "test message: " << userA->id << " => " << userB->id << std::endl;
  if (!userA->hasSessionFor(userB->id))
  {
    userA->initializeSession(userB->id);
    userA->getSessionByUserId(userB->id)->createOutbound(userB->keys.identityKeys, userB->keys.oneTimeKeys, 0);
  }
  std::string message = Tools::getInstance().generateRandomMessage();
  std::tuple<OlmBuffer, size_t> encryptedData = userA->encrypt(userB->id, message);
  std::cout << "encrypting: " << message << std::endl;

  if (!userB->hasSessionFor(userA->id))
  {
    userB->initializeSession(userA->id);
    userB->getSessionByUserId(userA->id)->createInbound(std::get<0>(encryptedData), userA->keys.identityKeys);
  }

  std::string decrypted = userB->decrypt(userA->id, encryptedData, message.size(), userA->keys.identityKeys);
  std::cout << "decrypted:  " << decrypted << std::endl;

  if (memcmp(message.data(), decrypted.data(), message.size()) != 0)
  {
    throw new std::runtime_error("decrypted message doesn't match the original one: [" + message + "] != [" + decrypted + "]");
  }
}

void doTest()
{
  std::vector<std::unique_ptr<User>> users;
  for (size_t i = 0; i < 10; ++i)
  {
    std::unique_ptr<User> user(new User(std::to_string(1000 + i)));
    user->initialize();
    users.push_back(move(user));
  }
  std::cout << "initialized" << std::endl;

  auto resetAndRepickle = [&users](size_t userIndex) {
    std::string pickleKey = Tools::getInstance().generateRandomString(20);
    Persist pickledReceiver = users.at(userIndex)->storeAsB64(pickleKey);
    std::string receiverId = users.at(userIndex)->id;
    users.at(userIndex).reset(new User(receiverId));
    users.at(userIndex)->restoreFromB64(pickleKey, pickledReceiver);
  };

  for (size_t i = 0; i < 250; ++i)
  {
    size_t senderIndex, receiverIndex;

    // randomly pick sender and receiver
    senderIndex = rand() % users.size();
    do
    {
      receiverIndex = rand() % users.size();
    } while (senderIndex == receiverIndex);
    // reset'n'repickle
    // 0 - reset sender
    // 1 - reset receiver
    // 2 - reset both
    size_t repickleOption = rand() % 3;
    if (repickleOption == 0)
    {
      resetAndRepickle(senderIndex);
    }
    else if (repickleOption == 1)
    {
      resetAndRepickle(receiverIndex);
    }
    else
    {
      resetAndRepickle(senderIndex);
      resetAndRepickle(receiverIndex);
    }

    messageTest(&(*users.at(senderIndex)), &(*users.at(receiverIndex)));
  }
  std::cout << "TEST PASSED!" << std::endl;
}

int main()
{
  std::cout << "HELLO" << std::endl;

  try
  {
    while (Tools::getInstance().messageIndex < 2000)
    {
      doTest();
    }
  }
  catch (std::runtime_error &err)
  {
    std::cout << "TEST FAILED with an error: " << err.what() << std::endl;
  }

  std::cout << "GOODBYE" << std::endl;

  return 0;
}
