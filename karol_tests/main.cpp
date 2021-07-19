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

enum class SessionType
{
  UNDEFINED = 0,
  INBOUND = 1,
  OUTBOUND = 2,
};

struct Session
{
  // should be passed from the owner User
  size_t userId;
  OlmAccount *ownerUserAccount;
  std::uint8_t *ownerIdentityKeys;

  //
  OlmSession *session;
  OlmBuffer sessionBuffer;
  SessionType type = SessionType::UNDEFINED;

  Session(
      size_t userId,
      OlmAccount *account,
      std::uint8_t *ownerIdentityKeys) : userId(userId),
                                         ownerUserAccount(account),
                                         ownerIdentityKeys(ownerIdentityKeys) {}

  /**
   * this should be used when we are sending a message
   */
  void createOutbound(
      OlmBuffer idKeys,
      OlmBuffer oneTimeKeys,
      size_t keyIndex)
  {
    if (this->type != SessionType::UNDEFINED)
    {
      throw runtime_error("error createOutbound => session already created");
    }
    this->sessionBuffer.resize(::olm_session_size());
    this->session = ::olm_session(this->sessionBuffer.data());
    OlmBuffer randomBuffer(::olm_create_outbound_session_random_length(this->session));

    if (-1 == generateRandomBuffer(
                  this->userId,
                  "create outbound",
                  randomBuffer,
                  olm_create_account_random_length(this->ownerUserAccount)))
    {
      throw runtime_error("error createOutbound => generateRandomBuffer");
    }
    if (-1 == ::olm_create_outbound_session(
                  this->session,
                  this->ownerUserAccount,
                  idKeys.data() + 15, // B's curve25519 identity key
                  43,
                  oneTimeKeys.data() + 25 + (43 + 12) * keyIndex, // B's curve25519 one time key
                  43,
                  randomBuffer.data(),
                  randomBuffer.size()))
    {
      throw runtime_error("error createOutbound => olm_create_outbound_session");
    }
    this->type = SessionType::OUTBOUND;
  }

  /**
   * this should be used when we are receiving a message
   */
  void createInbound(OlmBuffer encryptedMessage, OlmBuffer idKeys)
  {
    if (this->type != SessionType::UNDEFINED)
    {
      throw runtime_error("error createOutbound => session already created");
    }
    OlmBuffer tmpEncryptedMessage(encryptedMessage);
    this->sessionBuffer.resize(::olm_account_size());
    this->session = ::olm_session(this->sessionBuffer.data());
    if (-1 == ::olm_create_inbound_session(
                  this->session,
                  this->ownerUserAccount,
                  tmpEncryptedMessage.data(),
                  encryptedMessage.size()))
    {
      throw runtime_error("error createInbound => olm_create_inbound_session");
    }
    // Check that the inbound session matches the message it was created from.
    std::memcpy(tmpEncryptedMessage.data(), encryptedMessage.data(), encryptedMessage.size());
    if (1 != ::olm_matches_inbound_session(
                 this->session,
                 tmpEncryptedMessage.data(),
                 encryptedMessage.size()))
    {
      throw runtime_error("error createInbound => olm_matches_inbound_session");
    }

    // Check that the inbound session matches the key this message is supposed
    // to be from.
    std::memcpy(tmpEncryptedMessage.data(), encryptedMessage.data(), encryptedMessage.size());
    if (1 != ::olm_matches_inbound_session_from(
                 this->session,
                 idKeys.data() + 15, // A's curve125519 identity key
                 43,
                 tmpEncryptedMessage.data(),
                 encryptedMessage.size()))
    {
      throw runtime_error("error createInbound => olm_matches_inbound_session_from");
    }

    // Check that the inbound session isn't from a different user.
    std::memcpy(tmpEncryptedMessage.data(), encryptedMessage.data(), encryptedMessage.size());
    if (0 != ::olm_matches_inbound_session_from(
                 this->session,
                 ownerIdentityKeys + 15, // B's curve25519 identity key.
                 43,
                 tmpEncryptedMessage.data(),
                 encryptedMessage.size()))
    {
      throw runtime_error("error createInbound => olm_matches_inbound_session_from");
    }
    this->type = SessionType::INBOUND;
  }

  OlmBuffer storeAsB64(string secretKey)
  {
    size_t pickleLength = ::olm_pickle_session_length(this->session);
    OlmBuffer pickle(pickleLength);
    size_t res = ::olm_pickle_session(
        this->session,
        secretKey.data(),
        secretKey.size(),
        pickle.data(),
        pickleLength);
    if (pickleLength != res)
    {
      throw runtime_error("error pickleSession => olm_pickle_session");
    }
    return pickle;
  }

  void restoreFromB64(string secretKey, OlmBuffer b64)
  {
    this->sessionBuffer.resize(olm_session_size());
    this->session = olm_session(this->sessionBuffer.data());
    if (-1 == olm_unpickle_session(
                  this->session,
                  secretKey.data(),
                  secretKey.size(),
                  b64.data(),
                  b64.size()))
    {
      throw runtime_error("error pickleSession => olm_unpickle_session");
    }
    if (b64.size() != olm_pickle_session_length(this->session))
    {
      throw runtime_error("error pickleSession => olm_pickle_session_length");
    }
  }
};

struct User
{
  const size_t userId;

  OlmAccount *account;
  OlmBuffer accountBuffer;

  PreKeyBundle preKeyBundle;

  unique_ptr<Session> session;

  User(size_t userId) : userId(userId) {}

  void initialize()
  {
    this->createAccount();
    this->generatePreKeyBundle();
    this->initializeSession();
  }

  void createAccount()
  {
    OlmBuffer random;
    this->accountBuffer.resize(olm_account_size());
    this->account = olm_account(this->accountBuffer.data());
    if (-1 == generateRandomBuffer(
                  this->userId,
                  "create account",
                  random,
                  olm_create_account_random_length(this->account)))
    {
      throw runtime_error("error createAccount => generateRandomBuffer");
    }

    if (-1 == olm_create_account(
                  this->account,
                  random.data(),
                  random.size()))
    {
      throw runtime_error("error createAccount => olm_create_account");
    };
  }

  void initializeSession()
  {
    this->session.reset(new Session(
        this->userId,
        this->account,
        this->preKeyBundle.identityKeys.data()));
  }

  void getPublicIdentityKeys()
  {
    // this in fact doesn't really generate identity keys, it just puts them
    // in the pre key bundle struct object
    // those keys are generated when the account is created
    this->preKeyBundle.identityKeys.resize(olm_account_identity_keys_length(this->account));
    if (-1 == olm_account_identity_keys(
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
                  olm_account_generate_one_time_keys_random_length(
                      this->account,
                      oneTimeKeysAmount)))
    {
      throw runtime_error("error generateOneTimeKeys => generateRandomBuffer");
    }

    if (-1 == olm_account_generate_one_time_keys(
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
    this->preKeyBundle.oneTimeKeys.resize(olm_account_one_time_keys_length(this->account));
    if (-1 == olm_account_one_time_keys(
                  this->account,
                  this->preKeyBundle.oneTimeKeys.data(),
                  this->preKeyBundle.oneTimeKeys.size()))
    {
      throw runtime_error("error publishOneTimeKeys => olm_account_one_time_keys");
    }
    return olm_account_mark_keys_as_published(this->account);
  }

  void generatePreKeyBundle(size_t oneTimeKeysAmount = 50)
  {
    this->getPublicIdentityKeys();
    this->generateOneTimeKeys(oneTimeKeysAmount);
    size_t publishedOneTimeKeys = this->publishOneTimeKeys();
    if (publishedOneTimeKeys != oneTimeKeysAmount)
    {
      throw runtime_error("error generatePreKeyBundle => invalid amount of one-time keys published. Expected " + to_string(oneTimeKeysAmount) + ", got " + to_string(publishedOneTimeKeys));
    }
  }

  OlmBuffer storeAsB64(string secretKey)
  {
    size_t pickleLength = olm_pickle_account_length(this->account);
    OlmBuffer pickleBuffer(pickleLength);
    if (pickleLength != olm_pickle_account(
                            this->account,
                            secretKey.data(),
                            secretKey.size(),
                            pickleBuffer.data(),
                            pickleLength))
    {
      throw runtime_error("error storeAsB64 => olm_pickle_account");
    }
    return pickleBuffer;
  }

  void restoreFromB64(string secretKey, OlmBuffer &b64)
  {
    this->accountBuffer.resize(olm_account_size());
    this->account = olm_account(this->accountBuffer.data());
    if (-1 == olm_unpickle_account(
                  this->account,
                  secretKey.data(),
                  secretKey.size(),
                  b64.data(),
                  b64.size()))
    {
      throw runtime_error("error restoreFromB64 => olm_unpickle_account");
    }
    if (b64.size() != olm_pickle_account_length(this->account))
    {
      throw runtime_error("error restoreFromB64 => olm_pickle_account_length");
    }
    this->generatePreKeyBundle();
    this->initializeSession();
  }
};

int main()
{
  cout << "HELLO" << endl;
  srand((unsigned)time(0));

  unique_ptr<User> userA(new User(2785));
  userA->initialize();

  // we have to store this encrypted
  string pickleKey = "secret48570";

  unique_ptr<User> userB(new User(2735));
  userB->initialize();

  userA->session->createOutbound(userB->preKeyBundle.identityKeys, userB->preKeyBundle.oneTimeKeys, 0);

  OlmBuffer box(userA->session->sessionBuffer);

  OlmBuffer pickledSession = userA->session->storeAsB64(pickleKey);
  userA->session->restoreFromB64(pickleKey, pickledSession);

  cout << "TEST PASSED? ";
  if (memcmp(box.data(), userA->session->sessionBuffer.data(), box.size()) == 0)
  {
    cout << "YES";
  }
  else
  {
    cout << "NO";
  }
  cout << endl;

  cout << "GOODBYE" << endl;

  return 0;
}
