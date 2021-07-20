#include "olm/olm.h"
#include "olm/pk.h"

#include <iostream>

#include <vector>
#include <tuple>
#include <memory>
#include <cstdlib>

#include "tools.h"
#include "user.h"

using namespace std;

int main()
{
  cout << "HELLO" << endl;
  srand((unsigned)time(0));

  size_t idA = 2785;
  size_t idB = 2787;
  string pickleKeyA = "pickleA";
  string pickleKeyB = "pickleB";

  unique_ptr<User> userA(new User(idA));
  userA->initialize();

  unique_ptr<User> userB(new User(idB));
  userB->initialize();

  for (size_t i = 0; i < 5; ++i) {
    if (i > 0)
    {
      cout << "trying pickling A" << endl;
      OlmBuffer pickledA = userA->storeAsB64(pickleKeyA);
      OlmBuffer pickledSessionA = userA->session->storeAsB64(pickleKeyA);
      cout << "pickled" << endl;

      userA.reset(new User(idA));
      userA->restoreFromB64(pickleKeyA, pickledA);
      userA->session->restoreFromB64(pickleKeyA, pickledSessionA);
      cout << "unpickled" << endl;
      //

      cout << "trying pickling B" << endl;
      OlmBuffer pickledB = userB->storeAsB64(pickleKeyB);
      OlmBuffer pickledSessionB = userB->session->storeAsB64(pickleKeyB);
      cout << "pickled" << endl;

      userB.reset(new User(idB));
      userB->restoreFromB64(pickleKeyB, pickledB);
      userB->session->restoreFromB64(pickleKeyB, pickledSessionB);
      cout << "unpickled" << endl;
    }
    if (userA->session->session == nullptr)
    {
      userA->session->createOutbound(userB->preKeyBundle.identityKeys, userB->preKeyBundle.oneTimeKeys, 0);
    }

    string message = generateRandomMessage(50);

    tuple<OlmBuffer, size_t> encryptedData = userA->encrypt(message);
    cout << "encrypting: " << message << endl;

    if (userB->session->session == nullptr) {
      userB->session->createInbound(get<0>(encryptedData), userA->preKeyBundle.identityKeys);
    }

    string decrypted = userB->decrypt(encryptedData, message.size());
    cout << "decrypted:  " << decrypted << endl;

    if (memcmp(message.data(), decrypted.data(), message.size()) != 0) {
      throw new runtime_error("decrypted message doesn't match the original one: ["+ message +"] != ["+ decrypted +"]");
    }
  }
  cout << "TEST PASSED!" << endl;

  cout << "GOODBYE" << endl;

  return 0;
}
