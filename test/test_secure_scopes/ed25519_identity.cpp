// Native test implementation of the Identity methods needed by SecureScopes, using the bundled
// orlp ed25519 library (src/Identity.cpp depends on Arduino-only crypto libs).
#include <Identity.h>
#include <ed_25519.h>
#include <string.h>

namespace mesh {

Identity::Identity() {
  memset(pub_key, 0, sizeof(pub_key));
}

bool Identity::verify(const uint8_t* sig, const uint8_t* message, int msg_len) const {
  return ed25519_verify(sig, message, msg_len, pub_key) == 1;
}

LocalIdentity::LocalIdentity() {
  memset(prv_key, 0, sizeof(prv_key));
}

void LocalIdentity::sign(uint8_t* sig, const uint8_t* message, int msg_len) const {
  ed25519_sign(sig, message, msg_len, pub_key, prv_key);
}

void LocalIdentity::readFrom(const uint8_t* src, size_t len) {
  if (len == PRV_KEY_SIZE) {
    memcpy(prv_key, src, PRV_KEY_SIZE);
    ed25519_derive_pub(pub_key, prv_key);
  }
}

}
