#pragma once

#include "olm/olm.h"

#include <vector>

#include "tools.h"
#include "session.h"

using namespace std;

struct PreKeyBundle
{
  OlmBuffer identityKeys; // size = 116
  OlmBuffer oneTimeKeys;  // size = 43 each
};

struct User
{
  const string userId;

  OlmAccount *account;
  OlmBuffer accountBuffer;

  PreKeyBundle preKeyBundle;

  unique_ptr<Session> session;

  User(string userId) : userId(userId) {}

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
    generateRandomBuffer(
        this->userId,
        "create account",
        random,
        olm_create_account_random_length(this->account));

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
    generateRandomBuffer(
        this->userId,
        "one time keys",
        random,
        olm_account_generate_one_time_keys_random_length(
            this->account,
            oneTimeKeysAmount));

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
    // min 438, max 9504
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

  // encryptedMessage, messageType
  tuple<OlmBuffer, size_t> encrypt(string encrypted)
  {
    OlmBuffer encryptedMessage(
        olm_encrypt_message_length(this->session->session, encrypted.size()));
    OlmBuffer messageRandom;
    messageRandom.resize(olm_encrypt_random_length(this->session->session));
    generateRandomBuffer(
        this->userId,
        "encrypt",
        messageRandom,
        messageRandom.size());
    size_t messageType = olm_encrypt_message_type(this->session->session);
    if (-1 == olm_encrypt(
                  this->session->session,
                  (uint8_t *)encrypted.data(),
                  encrypted.size(),
                  messageRandom.data(),
                  messageRandom.size(),
                  encryptedMessage.data(),
                  encryptedMessage.size()))
    {
      throw runtime_error("error encrypt => olm_encrypt");
    }
    return {encryptedMessage, messageType};
  }

  string decrypt(tuple<std::vector<std::uint8_t>, size_t> encryptedData, size_t originalSize)
  {
    std::vector<std::uint8_t> encryptedMessage = get<0>(encryptedData);
    size_t messageType = get<1>(encryptedData);

    std::vector<std::uint8_t> tmpEncryptedMessage(encryptedMessage);
    size_t size = ::olm_decrypt_max_plaintext_length(
        this->session->session, messageType, tmpEncryptedMessage.data(), tmpEncryptedMessage.size());
    std::vector<std::uint8_t> decryptedMessage(size);
    size_t res = ::olm_decrypt(
        this->session->session,
        messageType,
        encryptedMessage.data(),
        encryptedMessage.size(),
        decryptedMessage.data(),
        decryptedMessage.size());
    if (std::size_t(originalSize) != res)
    {
      throw runtime_error("error olm_decrypt " + to_string(res));
    }
    decryptedMessage.resize(originalSize);
    string result = (char *)decryptedMessage.data();
    result.resize(originalSize);
    return result;
  }
};