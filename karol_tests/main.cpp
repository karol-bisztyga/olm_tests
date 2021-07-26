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

using namespace std;

void messageTest(User *userA, User *userB)
{
  cout << "test message: " << userA->userId << " => " << userB->userId << endl;
  if (!userA->hasSessionFor(userB->userId))
  {
    userA->initializeSession(userB->userId);
    userA->sessions.at(userB->userId)->createOutbound(userB->preKeyBundle.identityKeys, userB->preKeyBundle.oneTimeKeys, 0);
  }
  string message = generateRandomMessage();
  tuple<OlmBuffer, size_t> encryptedData = userA->encrypt(userB->userId, message);
  cout << "encrypting: " << message << endl;

  if (!userB->hasSessionFor(userA->userId))
  {
    userB->initializeSession(userA->userId);
    userB->sessions.at(userA->userId)->createInbound(get<0>(encryptedData), userA->preKeyBundle.identityKeys);
  }

  string decrypted = userB->decrypt(userA->userId, encryptedData, message.size());
  cout << "decrypted:  " << decrypted << endl;

  if (memcmp(message.data(), decrypted.data(), message.size()) != 0)
  {
    throw new runtime_error("decrypted message doesn't match the original one: [" + message + "] != [" + decrypted + "]");
  }
}

void doTest()
{
  vector<unique_ptr<User>> users;
  for (size_t i = 0; i < 10; ++i)
  {
    unique_ptr<User> user(new User(to_string(1000 + i)));
    user->initialize();
    users.push_back(move(user));
  }
  cout << "initialized" << endl;

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
    string senderKey = generateRandomString(20);
    Persist pickledSender = users.at(senderIndex)->storeAsB64(senderKey);
    string senderId = users.at(senderIndex)->userId;
    users.at(senderIndex).reset(new User(senderId));
    users.at(senderIndex)->restoreFromB64(senderKey, pickledSender);

    string receiverKey = generateRandomString(20);
    Persist pickledReceiver = users.at(receiverIndex)->storeAsB64(receiverKey);
    string receiverId = users.at(receiverIndex)->userId;
    users.at(receiverIndex).reset(new User(receiverId));
    users.at(receiverIndex)->restoreFromB64(receiverKey, pickledReceiver);

    messageTest(&(*users.at(senderIndex)), &(*users.at(receiverIndex)));
  }
  cout << "TEST PASSED!" << endl;
}

int main()
{
  cout << "HELLO" << endl;
  srand((unsigned)time(0));

  while (messageIndex < 600)
  {
    doTest();
  }

  cout << "GOODBYE" << endl;

  return 0;
}
