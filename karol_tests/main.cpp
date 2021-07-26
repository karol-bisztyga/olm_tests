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
  string idA = "1000";
  string idB = "2000";
  string idC = "3000";
  string pickleKeyA = "CFm9YKyRapXBXGxrew64";
  string pickleKeyB = "s3hwR4MsAKj6C3CYItdG";
  string pickleKeyC = "6KmB65eF6HZ2NPXi31vj";

  unique_ptr<User> userA(new User(idA));
  userA->initialize();

  unique_ptr<User> userB(new User(idB));
  userB->initialize();

  unique_ptr<User> userC(new User(idC));
  userC->initialize();

  cout << "initialized" << endl;
  for (size_t i = 0; i < 10; ++i)
  {
    if (true)
    {
      // pickle and unpickle A
      Persist pickledA = userA->storeAsB64(pickleKeyA);
      userA.reset(new User(idA));
      userA->restoreFromB64(pickleKeyA, pickledA);

      // pickle and unpickle B
      Persist pickledB = userB->storeAsB64(pickleKeyB);
      userB.reset(new User(idB));
      userB->restoreFromB64(pickleKeyB, pickledB);

      // pickle and unpickle C
      Persist pickledC = userC->storeAsB64(pickleKeyC);
      userC.reset(new User(idC));
      userC->restoreFromB64(pickleKeyC, pickledC);
    }

    int rnd = rand() % 6;
    if (rnd == 0)
    {
      messageTest(&(*userA), &(*userB));
    }
    else if (rnd == 1)
    {
      messageTest(&(*userA), &(*userC));
    }
    else if (rnd == 2)
    {
      messageTest(&(*userB), &(*userA));
    }
    else if (rnd == 3)
    {
      messageTest(&(*userB), &(*userC));
    }
    else if (rnd == 4)
    {
      messageTest(&(*userC), &(*userA));
    }
    else
    {
      messageTest(&(*userC), &(*userB));
    }
  }
  cout << "TEST PASSED!" << endl;
}

int main()
{
  cout << "HELLO" << endl;
  srand((unsigned)time(0));

  while (messageIndex < 300)
  {
    doTest();
  }

  cout << "GOODBYE" << endl;

  return 0;
}
