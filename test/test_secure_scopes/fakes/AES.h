#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Functional (NOT secure) stand-in for AES128: a reversible, key-dependent block transform,
// so that tests can check what receivers decrypt.
class AES128 {
  uint8_t _key[16];
public:
  void setKey(const uint8_t* key, size_t keySize) { memcpy(_key, key, 16); }
  void encryptBlock(uint8_t* output, const uint8_t* input) {
    for (int i = 0; i < 16; i++) output[i] = input[i] ^ _key[i] ^ (uint8_t)(i * 37 + 11);
  }
  void decryptBlock(uint8_t* output, const uint8_t* input) { encryptBlock(output, input); }
};
