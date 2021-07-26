#pragma once

#include "olm/olm.h"

#include <stdexcept>

#include "tools.h"

struct Session
{
  // should be passed from the owner User
  std::string userId;
  OlmAccount *ownerUserAccount;
  std::uint8_t *ownerIdentityKeys;
  MockRandom *mockRandom;

  //
  OlmSession *session = nullptr;
  OlmBuffer sessionBuffer;

  Session(
      std::string userId,
      OlmAccount *account,
      std::uint8_t *ownerIdentityKeys,
      MockRandom *mockRandom) : userId(userId),
                                ownerUserAccount(account),
                                ownerIdentityKeys(ownerIdentityKeys),
                                mockRandom(mockRandom) {}

  /**
   * this should be used when we are sending a message
   */
  void createOutbound(
      OlmBuffer idKeys,
      OlmBuffer oneTimeKeys,
      size_t keyIndex)
  {
    if (this->session != nullptr)
    {
      throw new std::runtime_error("error createOutbound => session already initialized");
    }
    this->sessionBuffer.resize(olm_session_size());
    this->session = olm_session(this->sessionBuffer.data());
    OlmBuffer randomBuffer(olm_create_outbound_session_random_length(this->session));

    (*this->mockRandom)(randomBuffer.data(), randomBuffer.size());

    if (-1 == olm_create_outbound_session(
                  this->session,
                  this->ownerUserAccount,
                  idKeys.data() + 15, // B's curve25519 identity key
                  43,
                  oneTimeKeys.data() + 25 + (43 + 12) * keyIndex, // B's curve25519 one time key
                  43,
                  randomBuffer.data(),
                  randomBuffer.size()))
    {
      throw std::runtime_error("error createOutbound => olm_create_outbound_session");
    }
  }

  /**
   * this should be used when we are receiving a message
   */
  void createInbound(OlmBuffer encryptedMessage, OlmBuffer idKeys)
  {
    if (this->session != nullptr)
    {
      throw new std::runtime_error("error createInbound => session already initialized");
    }
    OlmBuffer tmpEncryptedMessage(encryptedMessage);
    this->sessionBuffer.resize(olm_session_size());
    this->session = olm_session(this->sessionBuffer.data());
    if (-1 == olm_create_inbound_session(
                  this->session,
                  this->ownerUserAccount,
                  tmpEncryptedMessage.data(),
                  encryptedMessage.size()))
    {
      throw std::runtime_error("error createInbound => olm_create_inbound_session");
    }
    // Check that the inbound session matches the message it was created from.
    memcpy(tmpEncryptedMessage.data(), encryptedMessage.data(), encryptedMessage.size());
    if (1 != olm_matches_inbound_session(
                 this->session,
                 tmpEncryptedMessage.data(),
                 encryptedMessage.size()))
    {
      throw std::runtime_error("error createInbound => olm_matches_inbound_session");
    }

    // Check that the inbound session matches the key this message is supposed
    // to be from.
    memcpy(tmpEncryptedMessage.data(), encryptedMessage.data(), encryptedMessage.size());
    if (1 != olm_matches_inbound_session_from(
                 this->session,
                 idKeys.data() + 15, // A's curve125519 identity key
                 43,
                 tmpEncryptedMessage.data(),
                 encryptedMessage.size()))
    {
      throw std::runtime_error("error createInbound => olm_matches_inbound_session_from");
    }

    // Check that the inbound session isn't from a different user.
    memcpy(tmpEncryptedMessage.data(), encryptedMessage.data(), encryptedMessage.size());
    if (0 != olm_matches_inbound_session_from(
                 this->session,
                 ownerIdentityKeys + 15, // B's curve25519 identity key.
                 43,
                 tmpEncryptedMessage.data(),
                 encryptedMessage.size()))
    {
      throw std::runtime_error("error createInbound => olm_matches_inbound_session_from");
    }
  }

  OlmBuffer storeAsB64(std::string secretKey)
  {
    // min = 224, max = 4384
    size_t pickleLength = olm_pickle_session_length(this->session);
    OlmBuffer pickle(pickleLength);
    size_t res = olm_pickle_session(
        this->session,
        secretKey.data(),
        secretKey.size(),
        pickle.data(),
        pickleLength);
    if (pickleLength != res)
    {
      throw std::runtime_error("error pickleSession => olm_pickle_session");
    }
    return pickle;
  }

  void restoreFromB64(std::string secretKey, OlmBuffer b64)
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
      throw std::runtime_error("error pickleSession => olm_unpickle_session");
    }
    if (b64.size() != olm_pickle_session_length(this->session))
    {
      throw std::runtime_error("error pickleSession => olm_pickle_session_length");
    }
  }
};