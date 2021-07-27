#pragma once

#include "olm/olm.h"
#include "olm/session.hh"

#include <vector>
#include <unordered_map>
#include <utility>

#include "tools.h"
#include "session.h"
#include "persist.h"

struct PreKeyBundle
{
  OlmBuffer identityKeys; // size = 116
  OlmBuffer oneTimeKeys;  // size = 43 each
};

struct User
{
  const std::string userId;

  OlmAccount *account = nullptr;
  OlmBuffer accountBuffer;

  PreKeyBundle preKeyBundle;

  std::unordered_map<std::string, std::unique_ptr<Session>> sessions = {};

  User(std::string userId) : userId(userId) {}

  void initialize()
  {
    this->createAccount();
    this->generatePreKeyBundle();
  }

  void createAccount()
  {
    this->accountBuffer.resize(::olm_account_size());
    this->account = ::olm_account(this->accountBuffer.data());
    OlmBuffer randomAccountBuffer;
    generateRandomBytes(randomAccountBuffer, ::olm_create_account_random_length(this->account));

    size_t randomSize = ::olm_create_account_random_length(this->account);
    OlmBuffer randomBuffer;
    generateRandomBytes(randomBuffer, randomSize);

    if (-1 == ::olm_create_account(
                  this->account,
                  randomBuffer.data(),
                  randomSize))
    {
      throw std::runtime_error("error createAccount => ::olm_create_account");
    };
  }

  void initializeSession(std::string targetUserId)
  {
    if (this->sessions.find(targetUserId) != this->sessions.end())
    {
      throw std::runtime_error("error initializeSession => session already initialized");
    }
    std::unique_ptr<Session> newSession(new Session(
      this->userId,
      this->account,
      this->preKeyBundle.identityKeys.data()));
    this->sessions.insert(make_pair(targetUserId, std::move(newSession)));
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
      throw std::runtime_error("error generateIdentityKeys => ::olm_account_identity_keys");
    }
  }

  // max is MAX_ONE_TIME_KEYS = 100, we should generate more or less half of it
  void generateOneTimeKeys(size_t oneTimeKeysAmount)
  {
    OlmBuffer random;
    generateRandomBytes(random, ::olm_account_generate_one_time_keys_random_length(this->account, oneTimeKeysAmount));

    if (-1 == ::olm_account_generate_one_time_keys(
                  this->account,
                  oneTimeKeysAmount,
                  random.data(),
                  random.size()))
    {
      throw std::runtime_error("error generateOneTimeKeys => ::olm_account_generate_one_time_keys");
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
      throw std::runtime_error("error publishOneTimeKeys => ::olm_account_one_time_keys");
    }
    return ::olm_account_mark_keys_as_published(this->account);
  }

  void generatePreKeyBundle(size_t oneTimeKeysAmount = 50)
  {
    this->getPublicIdentityKeys();
    this->generateOneTimeKeys(oneTimeKeysAmount);
    size_t publishedOneTimeKeys = this->publishOneTimeKeys();
    if (publishedOneTimeKeys != oneTimeKeysAmount)
    {
      throw std::runtime_error("error generatePreKeyBundle => invalid amount of one-time keys published. Expected " + std::to_string(oneTimeKeysAmount) + ", got " + std::to_string(publishedOneTimeKeys));
    }
  }

  bool hasSessionFor(std::string targetUserId)
  {
    return (this->sessions.find(targetUserId) != this->sessions.end());
  }

  Persist storeAsB64(std::string secretKey)
  {
    Persist persist;
    // account
    size_t accountPickleLength = ::olm_pickle_account_length(this->account); // min 438, max 9504
    OlmBuffer accountPickleBuffer(accountPickleLength);
    if (accountPickleLength != ::olm_pickle_account(
                                   this->account,
                                   secretKey.data(),
                                   secretKey.size(),
                                   accountPickleBuffer.data(),
                                   accountPickleLength))
    {
      throw std::runtime_error("error storeAsB64 => ::olm_pickle_account");
    }
    persist.account = accountPickleBuffer;
    // sessions
    std::unordered_map<std::string, std::unique_ptr<Session>>::iterator it;
    for (it = this->sessions.begin(); it != this->sessions.end(); ++it)
    {
      OlmBuffer buffer = it->second->storeAsB64(secretKey);
      persist.sessions.insert(make_pair(it->first, buffer));
    }
    //
    return persist;
  }

  void restoreFromB64(std::string secretKey, Persist persist)
  {
    // account
    this->accountBuffer.resize(::olm_account_size());
    this->account = ::olm_account(this->accountBuffer.data());
    if (-1 == ::olm_unpickle_account(
                  this->account,
                  secretKey.data(),
                  secretKey.size(),
                  persist.account.data(),
                  persist.account.size()))
    {
      throw std::runtime_error("error restoreFromB64 => ::olm_unpickle_account");
    }
    if (persist.account.size() != ::olm_pickle_account_length(this->account))
    {
      throw std::runtime_error("error restoreFromB64 => ::olm_pickle_account_length");
    }
    this->generatePreKeyBundle();
    // sessions
    std::unordered_map<std::string, OlmBuffer>::iterator it;
    for (it = persist.sessions.begin(); it != persist.sessions.end(); ++it)
    {
      std::unique_ptr<Session> session(new Session(
          this->userId,
          this->account,
          this->preKeyBundle.identityKeys.data()));
      session->restoreFromB64(secretKey, it->second);
      this->sessions.insert(make_pair(it->first, move(session)));
    }
  }

  // encryptedMessage, messageType
  std::tuple<OlmBuffer, size_t> encrypt(std::string targetUserId, std::string encrypted)
  {
    if (this->sessions.find(targetUserId) == this->sessions.end())
    {
      this->initializeSession(targetUserId);
    }
    OlmSession *session = this->sessions.at(targetUserId)->session;
    OlmBuffer encryptedMessage(
        ::olm_encrypt_message_length(session, encrypted.size()));
    OlmBuffer messageRandom;
    generateRandomBytes(messageRandom, ::olm_encrypt_random_length(session));
    size_t messageType = ::olm_encrypt_message_type(session);
    if (-1 == ::olm_encrypt(
                  session,
                  (uint8_t *)encrypted.data(),
                  encrypted.size(),
                  messageRandom.data(),
                  messageRandom.size(),
                  encryptedMessage.data(),
                  encryptedMessage.size()))
    {
      throw std::runtime_error("error encrypt => ::olm_encrypt");
    }
    return {encryptedMessage, messageType};
  }

  std::string decrypt(std::string targetUserId, std::tuple<OlmBuffer, size_t> encryptedData, size_t originalSize)
  {
    if (this->sessions.find(targetUserId) == this->sessions.end())
    {
      this->initializeSession(targetUserId);
    }
    OlmSession *session = this->sessions.at(targetUserId)->session;
    OlmBuffer encryptedMessage = std::get<0>(encryptedData);
    size_t messageType = std::get<1>(encryptedData);

    OlmBuffer tmpEncryptedMessage(encryptedMessage);
    size_t size = ::olm_decrypt_max_plaintext_length(
        session, messageType, tmpEncryptedMessage.data(), tmpEncryptedMessage.size());
    OlmBuffer decryptedMessage(size);
    size_t res = ::olm_decrypt(
        session,
        messageType,
        encryptedMessage.data(),
        encryptedMessage.size(),
        decryptedMessage.data(),
        decryptedMessage.size());
    if (std::size_t(originalSize) != res)
    {
      throw std::runtime_error("error ::olm_decrypt");
    }
    decryptedMessage.resize(originalSize);
    std::string result = (char *)decryptedMessage.data();
    result.resize(originalSize);
    return result;
  }
};