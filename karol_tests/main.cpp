#include "olm/olm.h"
#include "olm/pk.h"

#include <iostream>

#include <vector>
#include <tuple>
#include <memory>
#include <cstdlib>

using namespace std;

#define KEYSIZE 43

typedef std::vector<std::uint8_t> OlmBuffer;

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
size_t generateRandomBuffer(
    size_t userId,
    string operationLabel,
    OlmBuffer &buffer,
    size_t bufferSize)
{
  if (bufferSize < sizeof(size_t) + operationLabel.size())
  {
    return -1;
  }
  buffer.resize(bufferSize);
  size_t i = 0;
  for (i = 0; i < sizeof(size_t); ++i)
  {
    buffer[i] = (userId >> i * 8) & 0xff;
  }
  for (char c : operationLabel)
  {
    buffer[++i] = c;
  }
  while (i++ < bufferSize)
  {
    buffer[i] = generateRandomByte();
  }
  return 0;
}

// TODO This is a problem, I don't know what is this message here
const string preKeySignatureMessage = "what is this message? :/";

struct PreKeyBundle
{
  OlmBuffer identityKeys; // size = 116
  OlmBuffer oneTimeKeys;  // size = 43 each
};

struct User
{
  const size_t userId;

  ::OlmAccount *account;
  OlmBuffer accountBuffer;

  PreKeyBundle preKeyBundle;

  User(size_t userId) : userId(userId) {}

  void createAccount()
  {
    OlmBuffer random;
    this->accountBuffer.resize(::olm_account_size());
    this->account = ::olm_account(this->accountBuffer.data());
    if (-1 == generateRandomBuffer(
                  this->userId,
                  "create account",
                  random,
                  ::olm_create_account_random_length(this->account)))
    {
      throw runtime_error("error createAccount => generateRandomBuffer");
    }

    if (-1 == ::olm_create_account(
                  this->account,
                  random.data(),
                  random.size()))
    {
      throw runtime_error("error createAccount => olm_create_account");
    };
  }

  void getPublicIdentityKeys()
  {
    // this in fact doesn't really generate identity keys, it just puts them
    // in the pre key bundle struct object
    // those keys are generated when the account is created
    this->preKeyBundle.identityKeys.resize(::olm_account_identity_keys_length(this->account));
    if (-1 == ::olm_account_identity_keys(
                  this->account,
                  this->preKeyBundle.identityKeys.data(),
                  this->preKeyBundle.identityKeys.size()))
    {
      throw runtime_error("error generateIdentityKeys => olm_account_identity_keys");
    }
  }

  // max is MAX_ONE_TIME_KEYS = 100, we should generate more or less half of it
  void generateOneTimeKeys(size_t oneTimeKeysAmount)
  {
    OlmBuffer random;
    if (-1 == generateRandomBuffer(
                  this->userId,
                  "one time keys",
                  random,
                  ::olm_account_generate_one_time_keys_random_length(
                      this->account,
                      oneTimeKeysAmount)))
    {
      throw runtime_error("error generateOneTimeKeys => generateRandomBuffer");
    }

    if (-1 == ::olm_account_generate_one_time_keys(
                  this->account,
                  oneTimeKeysAmount,
                  random.data(),
                  random.size()))
    {
      throw runtime_error("error generateOneTimeKeys => olm_account_generate_one_time_keys");
    }
  }

  // returns number of published keys
  size_t publishOneTimeKeys()
  {
    this->preKeyBundle.oneTimeKeys.resize(::olm_account_one_time_keys_length(this->account));
    if (-1 == ::olm_account_one_time_keys(
                  this->account,
                  this->preKeyBundle.oneTimeKeys.data(),
                  this->preKeyBundle.oneTimeKeys.size()))
    {
      throw runtime_error("error publishOneTimeKeys => olm_account_one_time_keys");
    }
    return olm_account_mark_keys_as_published(this->account);
  }

  void generatePreKeyBundle(size_t oneTimeKeysAmount)
  {
    this->getPublicIdentityKeys();
    this->generateOneTimeKeys(oneTimeKeysAmount);
    size_t publishedOneTimeKeys = this->publishOneTimeKeys();
    if (publishedOneTimeKeys != oneTimeKeysAmount)
    {
      throw runtime_error("error generatePreKeyBundle => invalid amount of one-time keys published. Expected " + to_string(oneTimeKeysAmount) + ", got " + to_string(publishedOneTimeKeys));
    }
  }
};

int main()
{
  cout << "HELLO" << endl;
  srand((unsigned)time(0));

  unique_ptr<User> userA(new User(2785));
  userA->createAccount();
  userA->generatePreKeyBundle(50);

  cout << "GOODBYE" << endl;

  return 0;
}