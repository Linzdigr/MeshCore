#include "SecureScopes.h"
#include <SHA256.h>
#include <string.h>

#define SCOPES_FILE_VERSION   1
#define MIN_VALID_EPOCH       1735689600UL   // 2025-01-01, before this the RTC is considered not set

// proof layout (offsets)
#define PROOF_SIG        0
#define PROOF_VER       64
#define PROOF_SCOPE     65
#define PROOF_HINT      66
#define PROOF_TIME      68
#define PROOF_MAGIC     76
#define PROOF_META_LEN  (SCOPE_PROOF_SIZE - SIGNATURE_SIZE)

static const uint8_t proof_magic[4] = { 'S', 'C', 'P', SCOPE_PROOF_VERSION };
static const char* scope_names[NUM_SECURE_SCOPES] = { "emergency", "admin", "private" };

SecureScopes::SecureScopes() {
  setDefaults();
  resetStats();
}

void SecureScopes::setDefaults() {
  memset(scopes, 0, sizeof(scopes));
  scopes[SCOPE_EMERGENCY].airtime_pct = DEFAULT_EMERGENCY_AIRTIME_PCT;
  scopes[SCOPE_EMERGENCY].pool_slots = DEFAULT_EMERGENCY_POOL_SLOTS;
  max_age = 0;
}

void SecureScopes::resetStats() {
  memset(n_verified, 0, sizeof(n_verified));
  memset(n_rejected, 0, sizeof(n_rejected));
  n_unknown = 0;
  memset(recent_sigs, 0, sizeof(recent_sigs));
  next_recent = 0;
}

const char* SecureScopes::getName(uint8_t scope_idx) {
  return scope_idx < NUM_SECURE_SCOPES ? scope_names[scope_idx] : "public";
}

const char* SecureScopes::getStatusName(uint8_t status) {
  switch (status) {
    case SCOPE_VERIFY_OK:      return "OK";
    case SCOPE_VERIFY_NO_KEY:  return "no-key";
    case SCOPE_VERIFY_BAD_SIG: return "bad-sig";
    case SCOPE_VERIFY_TOO_OLD: return "too-old";
    case SCOPE_VERIFY_REPLAY:  return "replay";
    default:                   return "no-proof";
  }
}

int SecureScopes::parseScope(const char* s) {
  if ((s[0] == 'S' || s[0] == 's') && s[1] >= '0' && s[1] < '0' + NUM_SECURE_SCOPES && s[2] == 0) return s[1] - '0';
  if (s[0] >= '0' && s[0] < '0' + NUM_SECURE_SCOPES && s[1] == 0) return s[0] - '0';
  for (int i = 0; i < NUM_SECURE_SCOPES; i++) {
    if (strcmp(s, scope_names[i]) == 0) return i;
  }
  return -1;  // unknown
}

int SecureScopes::getMACOffset(uint8_t payload_type) {
  switch (payload_type) {
    case PAYLOAD_TYPE_TXT_MSG:  return 2;                  // dest_hash, src_hash
    case PAYLOAD_TYPE_GRP_TXT:
    case PAYLOAD_TYPE_GRP_DATA: return 1;                  // channel_hash
    case PAYLOAD_TYPE_ANON_REQ: return 1 + PUB_KEY_SIZE;   // dest_hash, sender pub_key
    default:                    return -1;   // not signable (ACKs, adverts, paths, binary requests, ...)
  }
}

static bool needsTerminator(uint8_t payload_type) {
  return payload_type != PAYLOAD_TYPE_GRP_DATA;   // group data has an explicit length
}

void SecureScopes::calcMAC(const uint8_t* secret, const uint8_t* src, int len, uint8_t* mac) {
  SHA256 sha;   // same as Utils::encryptThenMAC()
  sha.resetHMAC(secret, PUB_KEY_SIZE);
  sha.update(src, len);
  sha.finalizeHMAC(secret, PUB_KEY_SIZE, mac, CIPHER_MAC_SIZE);
}

int SecureScopes::buildSignedMessage(uint8_t* dest, const mesh::Packet* pkt, int mac_offset, const uint8_t* proof) {
  int i = 0;
  dest[i++] = pkt->getPayloadType();
  int len = (proof - pkt->payload);   // everything before the proof
  memcpy(&dest[i], pkt->payload, len);
  memset(&dest[i + mac_offset], 0, CIPHER_MAC_SIZE);   // MAC covers the signature, so can't be signed
  i += len;
  memcpy(&dest[i], &proof[SIGNATURE_SIZE], PROOF_META_LEN);  i += PROOF_META_LEN;
  return i;
}

bool SecureScopes::sign(mesh::Packet* pkt, const uint8_t* secret, uint8_t scope_idx, const mesh::LocalIdentity& key, uint32_t timestamp) {
  int mac_offset = getMACOffset(pkt->getPayloadType());
  if (mac_offset < 0 || scope_idx >= NUM_SECURE_SCOPES) return false;

  int cipher_start = mac_offset + CIPHER_MAC_SIZE;
  int cipher_len = pkt->payload_len - cipher_start;
  if (cipher_len < CIPHER_BLOCK_SIZE || (cipher_len % CIPHER_BLOCK_SIZE) != 0) return false;   // not an encrypted payload

  // receivers read texts up to a null terminator, so make sure there is one before the proof
  bool add_block = false;
  if (needsTerminator(pkt->getPayloadType())) {
    uint8_t last[CIPHER_BLOCK_SIZE];
    mesh::Utils::decrypt(secret, last, &pkt->payload[pkt->payload_len - CIPHER_BLOCK_SIZE], CIPHER_BLOCK_SIZE);
    add_block = last[CIPHER_BLOCK_SIZE - 1] != 0;
  }
  if (pkt->payload_len + (add_block ? CIPHER_BLOCK_SIZE : 0) + SCOPE_PROOF_SIZE > MAX_PACKET_PAYLOAD) return false;  // won't fit

  if (add_block) {
    uint8_t zeroes[CIPHER_BLOCK_SIZE];
    memset(zeroes, 0, sizeof(zeroes));
    mesh::Utils::encrypt(secret, &pkt->payload[pkt->payload_len], zeroes, CIPHER_BLOCK_SIZE);
    pkt->payload_len += CIPHER_BLOCK_SIZE;
  }

  uint8_t* proof = &pkt->payload[pkt->payload_len];
  memset(proof, 0, SCOPE_PROOF_SIZE);
  proof[PROOF_VER] = SCOPE_PROOF_VERSION;
  proof[PROOF_SCOPE] = scope_idx;
  memcpy(&proof[PROOF_HINT], key.pub_key, 2);
  memcpy(&proof[PROOF_TIME], &timestamp, 4);
  memcpy(&proof[PROOF_MAGIC], proof_magic, sizeof(proof_magic));

  uint8_t message[1 + MAX_PACKET_PAYLOAD];
  int msg_len = buildSignedMessage(message, pkt, mac_offset, proof);
  key.sign(&proof[PROOF_SIG], message, msg_len);
  pkt->payload_len += SCOPE_PROOF_SIZE;

  // MAC must now cover the added blocks, for receivers to accept it
  calcMAC(secret, &pkt->payload[cipher_start], pkt->payload_len - cipher_start, &pkt->payload[mac_offset]);
  pkt->scope = scope_idx;
  return true;
}

bool SecureScopes::hasProof(const mesh::Packet* pkt) {
  int mac_offset = getMACOffset(pkt->getPayloadType());
  if (mac_offset < 0) return false;

  int cipher_len = pkt->payload_len - mac_offset - CIPHER_MAC_SIZE;
  if (cipher_len < CIPHER_BLOCK_SIZE + SCOPE_PROOF_SIZE || (cipher_len % CIPHER_BLOCK_SIZE) != 0) return false;

  const uint8_t* proof = &pkt->payload[pkt->payload_len - SCOPE_PROOF_SIZE];
  return memcmp(&proof[PROOF_MAGIC], proof_magic, sizeof(proof_magic)) == 0 && proof[PROOF_VER] == SCOPE_PROOF_VERSION;
}

uint8_t SecureScopes::verify(const mesh::Packet* pkt, uint32_t now, ScopeVerifyResult* res) {
  memset(res, 0, sizeof(*res));
  res->status = SCOPE_VERIFY_NO_PROOF;
  if (!hasProof(pkt)) return SCOPE_NONE;

  const uint8_t* proof = &pkt->payload[pkt->payload_len - SCOPE_PROOF_SIZE];
  res->scope_idx = proof[PROOF_SCOPE];
  res->key_hint = ((uint16_t)proof[PROOF_HINT] << 8) | proof[PROOF_HINT + 1];
  memcpy(&res->timestamp, &proof[PROOF_TIME], 4);

  uint8_t idx = res->scope_idx;
  if (!isActive(idx)) {
    res->status = SCOPE_VERIFY_NO_KEY;
    n_unknown++;
    return SCOPE_NONE;
  }

  uint8_t message[1 + MAX_PACKET_PAYLOAD];
  int msg_len = buildSignedMessage(message, pkt, getMACOffset(pkt->getPayloadType()), proof);

  const SecureScopeConfig& cfg = scopes[idx];
  for (int i = 0; i < cfg.num_keys && res->key == NULL; i++) {
    if (memcmp(cfg.pub_keys[i], &proof[PROOF_HINT], 2) != 0) continue;   // cheap filter, before the Ed25519 verify
    if (mesh::Identity(cfg.pub_keys[i]).verify(&proof[PROOF_SIG], message, msg_len)) {
      res->key = cfg.pub_keys[i];
    }
  }

  uint8_t status = SCOPE_VERIFY_OK;
  if (res->key == NULL) {
    status = SCOPE_VERIFY_BAD_SIG;
  } else if (max_age > 0 && now >= MIN_VALID_EPOCH       // only check age when our clock looks set
             && (res->timestamp + max_age < now || res->timestamp > now + max_age)) {
    status = SCOPE_VERIFY_TOO_OLD;
  } else {
    // exact copies are dropped by the 'seen' table. A copy with the same signature is an altered packet (eg. MAC)
    for (int i = 0; i < RECENT_PROOFS; i++) {
      if (memcmp(recent_sigs[i], &proof[PROOF_SIG], sizeof(recent_sigs[i])) == 0) {
        status = SCOPE_VERIFY_REPLAY;
        break;
      }
    }
  }
  res->status = status;
  if (status != SCOPE_VERIFY_OK) {
    n_rejected[idx]++;
    return SCOPE_NONE;
  }

  memcpy(recent_sigs[next_recent], &proof[PROOF_SIG], sizeof(recent_sigs[0]));
  next_recent = (next_recent + 1) % RECENT_PROOFS;
  n_verified[idx]++;
  return idx;
}

int SecureScopes::getTotalAirtimePct() const {
  int total = 0;
  for (int i = 0; i < NUM_SECURE_SCOPES; i++) total += scopes[i].airtime_pct;
  return total;
}

int SecureScopes::getTotalPoolSlots() const {
  int total = 0;
  for (int i = 0; i < NUM_SECURE_SCOPES; i++) total += scopes[i].pool_slots;
  return total;
}

bool SecureScopes::setAirtimeReserve(uint8_t scope_idx, int pct) {
  if (scope_idx >= NUM_SECURE_SCOPES || pct < 0) return false;
  if (getTotalAirtimePct() - scopes[scope_idx].airtime_pct + pct > MAX_SCOPE_AIRTIME_TOTAL) return false;
  scopes[scope_idx].airtime_pct = pct;
  return true;
}

bool SecureScopes::setPoolReserve(uint8_t scope_idx, int slots) {
  if (scope_idx >= NUM_SECURE_SCOPES || slots < 0) return false;
  if (getTotalPoolSlots() - scopes[scope_idx].pool_slots + slots > MAX_SCOPE_POOL_TOTAL) return false;
  scopes[scope_idx].pool_slots = slots;
  return true;
}

int SecureScopes::addKey(uint8_t scope_idx, const uint8_t* pub_key) {
  if (scope_idx >= NUM_SECURE_SCOPES) return -1;
  SecureScopeConfig& cfg = scopes[scope_idx];
  for (int i = 0; i < cfg.num_keys; i++) {
    if (memcmp(cfg.pub_keys[i], pub_key, PUB_KEY_SIZE) == 0) return 0;  // already present
  }
  if (cfg.num_keys >= MAX_SCOPE_KEYS) return -1;  // full
  memcpy(cfg.pub_keys[cfg.num_keys++], pub_key, PUB_KEY_SIZE);
  return 1;
}

int SecureScopes::removeKey(uint8_t scope_idx, const uint8_t* prefix, int prefix_len) {
  if (scope_idx >= NUM_SECURE_SCOPES || prefix_len <= 0 || prefix_len > PUB_KEY_SIZE) return 0;
  SecureScopeConfig& cfg = scopes[scope_idx];

  int match = -1;
  for (int i = 0; i < cfg.num_keys; i++) {
    if (memcmp(cfg.pub_keys[i], prefix, prefix_len) == 0) {
      if (match >= 0) return -1;   // ambiguous, need a longer prefix
      match = i;
    }
  }
  if (match < 0) return 0;  // not found

  cfg.num_keys--;
  for (int i = match; i < cfg.num_keys; i++) {
    memcpy(cfg.pub_keys[i], cfg.pub_keys[i + 1], PUB_KEY_SIZE);
  }
  memset(cfg.pub_keys[cfg.num_keys], 0, PUB_KEY_SIZE);
  return 1;
}

void SecureScopes::clearScope(uint8_t scope_idx) {
  if (scope_idx >= NUM_SECURE_SCOPES) return;
  memset(&scopes[scope_idx], 0, sizeof(scopes[scope_idx]));
}

#ifndef SECURE_SCOPES_NO_FS

static File openWrite(FILESYSTEM* _fs, const char* filename) {
  #if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
    _fs->remove(filename);
    return _fs->open(filename, FILE_O_WRITE);
  #elif defined(RP2040_PLATFORM)
    return _fs->open(filename, "w");
  #else
    return _fs->open(filename, "w", true);
  #endif
}

bool SecureScopes::load(FILESYSTEM* _fs, const char* path) {
  if (!path) path = "/scopes";
  if (!_fs->exists(path)) return false;

#if defined(RP2040_PLATFORM)
  File file = _fs->open(path, "r");
#else
  File file = _fs->open(path);
#endif
  if (!file) return false;

  SecureScopeConfig tmp[NUM_SECURE_SCOPES];
  uint32_t tmp_age;
  uint8_t ver;
  bool success = file.read(&ver, 1) == 1 && ver == SCOPES_FILE_VERSION;
  success = success && file.read((uint8_t *) &tmp_age, sizeof(tmp_age)) == sizeof(tmp_age);
  for (int i = 0; success && i < NUM_SECURE_SCOPES; i++) {
    auto s = &tmp[i];
    success = file.read(&s->airtime_pct, 1) == 1;
    success = success && file.read(&s->pool_slots, 1) == 1;
    success = success && file.read(&s->num_keys, 1) == 1 && s->num_keys <= MAX_SCOPE_KEYS;
    success = success && file.read((uint8_t *) s->pub_keys, sizeof(s->pub_keys)) == sizeof(s->pub_keys);
  }
  file.close();

  if (success) {   // only apply a complete, valid config
    memcpy(scopes, tmp, sizeof(scopes));
    max_age = tmp_age;
  }
  return success;
}

bool SecureScopes::save(FILESYSTEM* _fs, const char* path) {
  File file = openWrite(_fs, path ? path : "/scopes");
  if (!file) return false;

  uint8_t ver = SCOPES_FILE_VERSION;
  bool success = file.write(&ver, 1) == 1;
  success = success && file.write((uint8_t *) &max_age, sizeof(max_age)) == sizeof(max_age);
  for (int i = 0; success && i < NUM_SECURE_SCOPES; i++) {
    auto s = &scopes[i];
    success = file.write(&s->airtime_pct, 1) == 1;
    success = success && file.write(&s->pool_slots, 1) == 1;
    success = success && file.write(&s->num_keys, 1) == 1;
    success = success && file.write((uint8_t *) s->pub_keys, sizeof(s->pub_keys)) == sizeof(s->pub_keys);
  }
  file.close();
  return success;
}

#endif
