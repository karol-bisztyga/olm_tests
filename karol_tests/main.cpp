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
  std::cout << "test message: " << userA->userId << " => " << userB->userId << std::endl;
  if (!userA->hasSessionFor(userB->userId))
  {
    userA->initializeSession(userB->userId);
    userA->sessions.at(userB->userId)->createOutbound(userB->preKeyBundle.identityKeys, userB->preKeyBundle.oneTimeKeys, 0);
  }
  std::string message = generateRandomMessage();
  std::tuple<OlmBuffer, size_t> encryptedData = userA->encrypt(userB->userId, message);
  std::cout << "encrypting: " << message << std::endl;

  if (!userB->hasSessionFor(userA->userId))
  {
    userB->initializeSession(userA->userId);
    userB->sessions.at(userA->userId)->createInbound(std::get<0>(encryptedData), userA->preKeyBundle.identityKeys);
  }

  std::string decrypted = userB->decrypt(userA->userId, encryptedData, message.size());
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

  for (size_t i = 0; i < 100; ++i)
  {
    size_t senderIndex, receiverIndex;

    // randomly pick sender and receiver
    senderIndex = rand() % users.size();
    do
    {
      receiverIndex = rand() % users.size();
    } while (senderIndex == receiverIndex);
    // reset'n'repickle
    std::string senderKey = generateRandomString(20);
    Persist pickledSender = users.at(senderIndex)->storeAsB64(senderKey);
    std::string senderId = users.at(senderIndex)->userId;
    users.at(senderIndex).reset(new User(senderId));
    users.at(senderIndex)->restoreFromB64(senderKey, pickledSender);

    std::string receiverKey = generateRandomString(20);
    Persist pickledReceiver = users.at(receiverIndex)->storeAsB64(receiverKey);
    std::string receiverId = users.at(receiverIndex)->userId;
    users.at(receiverIndex).reset(new User(receiverId));
    users.at(receiverIndex)->restoreFromB64(receiverKey, pickledReceiver);

    messageTest(&(*users.at(senderIndex)), &(*users.at(receiverIndex)));
  }
  std::cout << "TEST PASSED!" << std::endl;
}

int main()
{
  std::cout << "HELLO" << std::endl;
  srand((unsigned)time(0));

  try
  {
    while (messageIndex < 600)
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
