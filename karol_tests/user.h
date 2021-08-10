#pragma once

#include "olm/olm.h"
#include "olm/session.hh"

#include <vector>
#include <unordered_map>
#include <utility>

#include "tools.h"
#include "session.h"
#include "persist.h"

class User
{

  OlmAccount *account = nullptr;
  OlmBuffer accountBuffer;

  std::unordered_map<std::string, std::shared_ptr<Session>> sessions = {};

public:
  const std::string id;
  Keys keys;

  User(std::string id) : id(id) {}

  void initialize();
  void createAccount();
  void initializeSession(std::string targetUserId);
  void getPublicIdentityKeys();
  void generateOneTimeKeys(size_t oneTimeKeysAmount);
  // returns number of published keys
  size_t publishOneTimeKeys();
  void generateKeys(size_t oneTimeKeysAmount = 50);
  bool hasSessionFor(std::string targetUserId);
  Persist storeAsB64(std::string secretKey);
  void restoreFromB64(std::string secretKey, Persist persist);
  // encryptedMessage, messageType
  std::tuple<OlmBuffer, size_t> encrypt(std::string targetUserId, std::string encrypted);
  std::string decrypt(std::string targetUserId, std::tuple<OlmBuffer, size_t> encryptedData, size_t originalSize, OlmBuffer &theirIdKeys);
  std::shared_ptr<Session> getSessionByUserId(std::string userId);
};