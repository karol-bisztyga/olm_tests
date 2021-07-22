#include "olm/olm.h"
#include "olm/pk.h"

#include <iostream>

#include <vector>
#include <tuple>
#include <memory>
#include <cstdlib>
#include <map>

#include "tools.h"
#include "user.h"
#include "persist.h"

using namespace std;


void messageTest(User *userA, User *userB){
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

  cout << "initialized" << endl;
  for (size_t i=0; i< 10; ++i)
  {
    // // pickle and unpickle A
    if (true)
    {
      Persist pickledA = userA->storeAsB64(pickleKeyA);
      userA.reset(new User(idA));
      userA->restoreFromB64(pickleKeyA, pickledA);

      // // pickle and unpickle B
      Persist pickledB = userB->storeAsB64(pickleKeyB);
      userB.reset(new User(idB));
      userB->restoreFromB64(pickleKeyB, pickledB);
    }

    int rnd = rand() % 2;
    if (rnd)
    {
      messageTest(&(*userA), &(*userB));
    }
    else
    {
      messageTest(&(*userB), &(*userA));
    }
    
  }
  cout << "TEST PASSED!" << endl;
}

int main()
{
  cout << "HELLO" << endl;
  srand((unsigned)time(0));

  while(true)
  {
    doTest();
  }

  cout << "GOODBYE" << endl;

  return 0;
}
