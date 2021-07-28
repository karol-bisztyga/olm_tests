#pragma once

#include "olm/olm.h"

#include <stdexcept>

#include "tools.h"

class Session
{
  // should be passed from the owner User
  std::string userId;
  OlmAccount *ownerUserAccount;
  std::uint8_t *ownerIdentityKeys;

  //
  OlmSession *session = nullptr;
  OlmBuffer sessionBuffer;

public:
  Session(
      std::string userId,
      OlmAccount *account,
      std::uint8_t *ownerIdentityKeys) : userId(userId),
                                         ownerUserAccount(account),
                                         ownerIdentityKeys(ownerIdentityKeys) {}

  /**
   * this should be used when we are sending a message
   */
  void createOutbound(OlmBuffer idKeys, OlmBuffer oneTimeKeys, size_t keyIndex);
  /**
   * this should be used when we are receiving a message
   */
  void createInbound(OlmBuffer encryptedMessage, OlmBuffer idKeys);
  OlmBuffer storeAsB64(std::string secretKey);
  void restoreFromB64(std::string secretKey, OlmBuffer b64);
  OlmSession *getSession();
};