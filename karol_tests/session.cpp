#include "session.h"

void Session::createOutbound(
    OlmBuffer idKeys,
    OlmBuffer oneTimeKeys,
    size_t keyIndex)
{
  if (this->session != nullptr)
  {
    throw new std::runtime_error("error createOutbound => session already initialized");
  }
  this->sessionBuffer.resize(::olm_session_size());
  this->session = ::olm_session(this->sessionBuffer.data());

  OlmBuffer randomBuffer;
  Tools::getInstance().generateRandomBytes(randomBuffer, ::olm_create_outbound_session_random_length(this->session));

  if (-1 == ::olm_create_outbound_session(
                this->session,
                this->ownerUserAccount,
                idKeys.data() + 15, // B's curve25519 identity key
                KEYSIZE,
                oneTimeKeys.data() + 25 + (KEYSIZE + 12) * keyIndex, // B's curve25519 one time key
                KEYSIZE,
                randomBuffer.data(),
                randomBuffer.size()))
  {
    throw std::runtime_error("error createOutbound => ::olm_create_outbound_session");
  }
}

void Session::createInbound(OlmBuffer encryptedMessage, OlmBuffer idKeys)
{
  if (this->session != nullptr)
  {
    throw new std::runtime_error("error createInbound => session already initialized");
  }
  OlmBuffer tmpEncryptedMessage(encryptedMessage);
  this->sessionBuffer.resize(::olm_session_size());
  this->session = ::olm_session(this->sessionBuffer.data());
  if (-1 == ::olm_create_inbound_session(
                this->session,
                this->ownerUserAccount,
                tmpEncryptedMessage.data(),
                encryptedMessage.size()))
  {
    throw std::runtime_error("error createInbound => ::olm_create_inbound_session");
  }
}

OlmBuffer Session::storeAsB64(std::string secretKey)
{
  // min = 224, max = 4384
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
    throw std::runtime_error("error pickleSession => ::olm_pickle_session");
  }
  return pickle;
}

void Session::restoreFromB64(std::string secretKey, OlmBuffer b64)
{
  this->sessionBuffer.resize(::olm_session_size());
  this->session = ::olm_session(this->sessionBuffer.data());
  if (-1 == ::olm_unpickle_session(
                this->session,
                secretKey.data(),
                secretKey.size(),
                b64.data(),
                b64.size()))
  {
    throw std::runtime_error("error pickleSession => ::olm_unpickle_session");
  }
  if (b64.size() != ::olm_pickle_session_length(this->session))
  {
    throw std::runtime_error("error pickleSession => ::olm_pickle_session_length");
  }
}

OlmSession *Session::getSession()
{
  return this->session;
}
