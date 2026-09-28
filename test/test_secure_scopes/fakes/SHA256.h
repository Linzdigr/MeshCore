#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Functional (NOT secure) stand-in for SHA256, including a keyed HMAC, so that MAC checks
// in Utils::MACThenDecrypt() really depend on the key and on every byte.
class SHA256 {
  uint8_t _state[32];
  size_t _len;
public:
  SHA256() { reset(); }
  void reset() { memset(_state, 0, sizeof(_state)); _len = 0; }

  void update(const void* data, size_t len) {
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < len; i++) {
      uint8_t b = bytes[i];
      _state[_len % 32] ^= b;
      _state[(_len + 1) % 32] += (uint8_t)((b >> 1) | (b << 7)) + (uint8_t)_len;
      _state[(_len * 7 + 3) % 32] ^= _state[_len % 32] * 31;
      _len++;
    }
  }
  void finalize(uint8_t* hash, size_t hashLen) {
    for (size_t i = 0; i < hashLen; i++) hash[i] = _state[i % 32];
  }
  void resetHMAC(const uint8_t* key, size_t keyLen) { reset(); update(key, keyLen); }
  void finalizeHMAC(const uint8_t* key, size_t keyLen, uint8_t* hash, size_t hashLen) {
    update(key, keyLen);
    finalize(hash, hashLen);
  }
};
