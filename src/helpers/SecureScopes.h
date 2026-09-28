#pragma once

#include <Packet.h>
#include <Identity.h>

#ifndef SECURE_SCOPES_NO_FS
  #include <helpers/IdentityStore.h>   // for FILESYSTEM
#endif

#ifndef MAX_SCOPE_KEYS
  #define MAX_SCOPE_KEYS           4    // max public keys (ie. teams) per scope
#endif
#define MAX_SCOPE_AIRTIME_TOTAL   50    // percent of TX budget, sum over all scopes
#define MAX_SCOPE_POOL_TOTAL      16    // packet pool slots, sum over all scopes

#define DEFAULT_EMERGENCY_AIRTIME_PCT  10
#define DEFAULT_EMERGENCY_POOL_SLOTS    4

#define SCOPE_PROOF_SIZE     80    // 5 cipher blocks, appended to the ciphertext
#define SCOPE_PROOF_VERSION   1
#define RECENT_PROOFS        16

/*
 * Secure scopes (S0 = emergency, S1 = admin, S2 = private).
 *
 * A scope is identified by one or more Ed25519 public keys, configured on repeaters. The matching private key
 * is only held by the team's companion, which signs the messages it floods.
 *
 * The packet itself is unchanged (route, transport codes, header, dest/src or channel hash), so that ANY
 * firmware version can forward it with its normal rules. A proof is appended to the ciphertext, and the MAC
 * is re-calculated to cover it:
 *
 *   payload = [prefix][MAC(2)][ciphertext][proof(80)]
 *   proof   = signature(64) | version(1) | scope_idx(1) | key_hint(2) | timestamp(4) | reserved(4) | magic "SCP\x01"(4)
 *   signed  = payload_type(1) | [prefix][00 00][ciphertext] | proof[64..80)
 *
 * Receivers (of any version) decrypt the proof blocks into trailing bytes, which are ignored: texts are read
 * up to their null terminator (the signer guarantees there is one), and group data has an explicit length.
 * So only payload types where this holds are signed: TXT_MSG, GRP_TXT, GRP_DATA, ANON_REQ (login).
 *
 * The MAC can't be signed (it covers the signature), so a copy with altered MAC bytes still has a valid
 * signature: repeaters remember recently verified signatures, and give no privileges to such copies.
 *
 * Repeaters only give a packet the scope's reservations (airtime, packet pool) and precedence once the
 * signature has been verified against one of the scope's keys. Reservations are only in effect while
 * the scope has at least one key.
 */

struct SecureScopeConfig {
  uint8_t airtime_pct;   // percent of TX budget, reserved for this scope
  uint8_t pool_slots;    // num of packet pool slots, reserved for this scope
  uint8_t num_keys;
  uint8_t pub_keys[MAX_SCOPE_KEYS][PUB_KEY_SIZE];
};

#define SCOPE_VERIFY_NO_PROOF   0
#define SCOPE_VERIFY_OK         1
#define SCOPE_VERIFY_NO_KEY     2    // claimed scope has no keys on this node
#define SCOPE_VERIFY_BAD_SIG    3    // no key matches, or payload was altered
#define SCOPE_VERIFY_TOO_OLD    4
#define SCOPE_VERIFY_REPLAY     5    // signature already seen, on a different packet

struct ScopeVerifyResult {
  uint8_t status;       // one of SCOPE_VERIFY_*
  uint8_t scope_idx;    // claimed scope
  uint16_t key_hint;
  uint32_t timestamp;
  const uint8_t* key;   // the verifying public key (if OK)
};

class SecureScopes {
  SecureScopeConfig scopes[NUM_SECURE_SCOPES];
  uint32_t max_age;      // seconds, 0 = timestamps not checked
  uint32_t n_verified[NUM_SECURE_SCOPES];
  uint32_t n_rejected[NUM_SECURE_SCOPES];
  uint32_t n_unknown;    // claimed scope has no keys, or is invalid
  uint8_t recent_sigs[RECENT_PROOFS][8];
  uint8_t next_recent;

  static int getMACOffset(uint8_t payload_type);
  static int buildSignedMessage(uint8_t* dest, const mesh::Packet* pkt, int mac_offset, const uint8_t* proof);
  static void calcMAC(const uint8_t* secret, const uint8_t* src, int len, uint8_t* mac);

public:
  SecureScopes();

  static const char* getName(uint8_t scope_idx);
  static int parseScope(const char* s);    // "S0", "0", "emergency", ...  returns -1 if unknown
  static const char* getStatusName(uint8_t status);

  /**
   * \returns  true if this payload type can carry a proof, without breaking receivers
   */
  static bool isSignable(uint8_t payload_type) { return getMACOffset(payload_type) >= 0; }

  /**
   * \brief  appends the proof to a packet created by createDatagram()/createGroupDatagram()/createAnonDatagram(),
   *         and re-calculates its MAC. Route and transport codes are not touched.
   * \param  secret   the secret the payload was encrypted with (ie. contact shared secret, or channel secret)
   * \returns  false if the payload type is not signable, or the proof does not fit (packet is left unchanged)
   */
  static bool sign(mesh::Packet* pkt, const uint8_t* secret, uint8_t scope_idx, const mesh::LocalIdentity& key, uint32_t timestamp);

  /**
   * \returns  true if packet's payload ends with a (not yet verified) scope proof
   */
  static bool hasProof(const mesh::Packet* pkt);

  /**
   * \param  now  current RTC time (epoch secs)
   * \returns  the verified scope index, or SCOPE_NONE
   */
  uint8_t verify(const mesh::Packet* pkt, uint32_t now, ScopeVerifyResult* result);

  void setDefaults();
  bool isActive(uint8_t scope_idx) const { return scope_idx < NUM_SECURE_SCOPES && scopes[scope_idx].num_keys > 0; }
  const SecureScopeConfig& getConfig(uint8_t scope_idx) const { return scopes[scope_idx]; }

  // effective reservations (zero while scope has no keys)
  uint8_t getAirtimeReservePct(uint8_t scope_idx) const { return isActive(scope_idx) ? scopes[scope_idx].airtime_pct : 0; }
  uint8_t getPoolReserve(uint8_t scope_idx) const { return isActive(scope_idx) ? scopes[scope_idx].pool_slots : 0; }

  bool setAirtimeReserve(uint8_t scope_idx, int pct);     // false if total would exceed MAX_SCOPE_AIRTIME_TOTAL
  bool setPoolReserve(uint8_t scope_idx, int slots);      // false if total would exceed MAX_SCOPE_POOL_TOTAL
  int getTotalAirtimePct() const;
  int getTotalPoolSlots() const;

  int addKey(uint8_t scope_idx, const uint8_t* pub_key);  // 1 = added, 0 = already present, -1 = table full
  int removeKey(uint8_t scope_idx, const uint8_t* prefix, int prefix_len);   // num removed, -1 if prefix is ambiguous
  void clearScope(uint8_t scope_idx);

  uint32_t getMaxAge() const { return max_age; }
  void setMaxAge(uint32_t secs) { max_age = secs; }

  uint32_t getNumVerified(uint8_t scope_idx) const { return n_verified[scope_idx]; }
  uint32_t getNumRejected(uint8_t scope_idx) const { return n_rejected[scope_idx]; }
  uint32_t getNumUnknown() const { return n_unknown; }
  void resetStats();

#ifndef SECURE_SCOPES_NO_FS
  bool load(FILESYSTEM* fs, const char* path = NULL);
  bool save(FILESYSTEM* fs, const char* path = NULL);
#endif
};
