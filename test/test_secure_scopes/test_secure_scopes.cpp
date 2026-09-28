#include <gtest/gtest.h>
#include <string>
#include <ed_25519.h>
#include <Dispatcher.h>
#include "helpers/SecureScopes.h"
#include "helpers/StaticPoolPacketManager.h"

using namespace mesh;

static const uint32_t NOW = 1790000000;   // a plausible (set) RTC time

static LocalIdentity makeKey(uint8_t seed_byte) {
  uint8_t seed[32], pub[PUB_KEY_SIZE], prv[PRV_KEY_SIZE];
  memset(seed, seed_byte, sizeof(seed));
  ed25519_create_keypair(pub, prv, seed);
  LocalIdentity id;
  id.readFrom(prv, PRV_KEY_SIZE);
  return id;
}

static const uint8_t* testSecret() {
  static uint8_t secret[PUB_KEY_SIZE];
  for (int i = 0; i < PUB_KEY_SIZE; i++) secret[i] = (uint8_t)(i * 13 + 5);
  return secret;
}

// same plaintext layout and encryption as BaseChatMesh::composeMsgPacket() + Mesh::createDatagram()
static Packet makeTextMsg(const char* text) {
  uint8_t temp[5 + 200];
  uint32_t ts = NOW;
  memcpy(temp, &ts, 4);
  temp[4] = 0;
  int text_len = strlen(text);
  memcpy(&temp[5], text, text_len + 1);

  Packet p;
  p.header = ROUTE_TYPE_TRANSPORT_FLOOD | (PAYLOAD_TYPE_TXT_MSG << PH_TYPE_SHIFT);
  p.transport_codes[0] = 0x1234;   // some Region
  p.transport_codes[1] = 0;
  p.payload[0] = 0xAA;  // dest hash
  p.payload[1] = 0xBB;  // src hash
  p.payload_len = 2 + Utils::encryptThenMAC(testSecret(), &p.payload[2], temp, 5 + text_len);
  return p;
}

// what a receiver (of ANY firmware version) does: Mesh::onRecvPacket() + BaseChatMesh::onPeerDataRecv()
static bool receiveText(const Packet& p, std::string& text) {
  uint8_t data[MAX_PACKET_PAYLOAD + 16];
  int len = Utils::MACThenDecrypt(testSecret(), data, &p.payload[2], p.payload_len - 2);
  if (len <= 0) return false;
  data[len] = 0;
  text = (const char*) &data[5];
  return true;
}

static Packet signedText(const LocalIdentity& key, uint8_t scope_idx, uint32_t ts, const char* text = "Need medical help at the bridge") {
  Packet p = makeTextMsg(text);
  EXPECT_TRUE(SecureScopes::sign(&p, testSecret(), scope_idx, key, ts));
  p.scope = SCOPE_UNCLASSIFIED;   // as received
  return p;
}

static uint8_t* proofOf(Packet& p) { return &p.payload[p.payload_len - SCOPE_PROOF_SIZE]; }

TEST(SecureScopes, SignedMessageIsStillReadableByAnyReceiver) {
  auto key = makeKey(1);
  Packet p = makeTextMsg("Need medical help at the bridge");
  int orig_len = p.payload_len;
  ASSERT_TRUE(SecureScopes::sign(&p, testSecret(), SCOPE_EMERGENCY, key, NOW));

  EXPECT_EQ(p.payload_len, orig_len + SCOPE_PROOF_SIZE);
  EXPECT_EQ(p.getRouteType(), ROUTE_TYPE_TRANSPORT_FLOOD);   // route and Region code untouched
  EXPECT_EQ(p.transport_codes[0], 0x1234);
  EXPECT_EQ(p.scope, SCOPE_EMERGENCY);
  EXPECT_TRUE(SecureScopes::hasProof(&p));

  std::string text;
  ASSERT_TRUE(receiveText(p, text));   // MAC still valid
  EXPECT_EQ(text, "Need medical help at the bridge");
}

TEST(SecureScopes, TextFillingABlockGetsATerminator) {
  auto key = makeKey(1);
  Packet p = makeTextMsg("11 chars ok");   // 5 + 11 = 16: no null terminator in the plaintext
  int orig_len = p.payload_len;
  ASSERT_TRUE(SecureScopes::sign(&p, testSecret(), SCOPE_EMERGENCY, key, NOW));
  EXPECT_EQ(p.payload_len, orig_len + CIPHER_BLOCK_SIZE + SCOPE_PROOF_SIZE);

  std::string text;
  ASSERT_TRUE(receiveText(p, text));
  EXPECT_EQ(text, "11 chars ok");
}

TEST(SecureScopes, GroupDataKeepsItsLength) {
  auto key = makeKey(1);
  uint8_t temp[3 + 20];
  temp[0] = 0x01; temp[1] = 0xFF;   // data type
  temp[2] = 20;                     // data len
  for (int i = 0; i < 20; i++) temp[3 + i] = 0xE0 + i;   // ends with non-zero: no extra block needed

  Packet p;
  p.header = ROUTE_TYPE_FLOOD | (PAYLOAD_TYPE_GRP_DATA << PH_TYPE_SHIFT);
  p.payload[0] = 0x42;  // channel hash
  p.payload_len = 1 + Utils::encryptThenMAC(testSecret(), &p.payload[1], temp, sizeof(temp));
  int orig_len = p.payload_len;
  ASSERT_TRUE(SecureScopes::sign(&p, testSecret(), SCOPE_PRIVATE, key, NOW));
  EXPECT_EQ(p.payload_len, orig_len + SCOPE_PROOF_SIZE);

  uint8_t data[MAX_PACKET_PAYLOAD + 16];
  int len = Utils::MACThenDecrypt(testSecret(), data, &p.payload[1], p.payload_len - 1);
  ASSERT_GT(len, 3 + 20);
  EXPECT_EQ(data[2], 20);
  EXPECT_EQ(memcmp(&data[3], &temp[3], 20), 0);
}

TEST(SecureScopes, OnlyMessageTypesAreSigned) {
  auto key = makeKey(1);
  for (uint8_t type : { PAYLOAD_TYPE_ACK, PAYLOAD_TYPE_ADVERT, PAYLOAD_TYPE_PATH, PAYLOAD_TYPE_REQ, PAYLOAD_TYPE_RESPONSE }) {
    Packet p = makeTextMsg("hello");
    p.header = ROUTE_TYPE_FLOOD | (type << PH_TYPE_SHIFT);
    int orig_len = p.payload_len;
    EXPECT_FALSE(SecureScopes::sign(&p, testSecret(), SCOPE_EMERGENCY, key, NOW)) << "type=" << (int)type;
    EXPECT_EQ(p.payload_len, orig_len);
  }
}

TEST(SecureScopes, TooBigIsLeftUnsigned) {
  auto key = makeKey(1);
  char text[121];
  memset(text, 'x', 120); text[120] = 0;
  Packet p = makeTextMsg(text);
  Packet orig = p;
  EXPECT_FALSE(SecureScopes::sign(&p, testSecret(), SCOPE_EMERGENCY, key, NOW));
  EXPECT_EQ(p.payload_len, orig.payload_len);
  EXPECT_EQ(memcmp(p.payload, orig.payload, p.payload_len), 0);
  EXPECT_FALSE(SecureScopes::hasProof(&p));
}

TEST(SecureScopes, VerifiesWithConfiguredKey) {
  auto key = makeKey(1);
  SecureScopes scopes;
  ASSERT_EQ(scopes.addKey(SCOPE_EMERGENCY, key.pub_key), 1);

  Packet p = signedText(key, SCOPE_EMERGENCY, NOW - 3);
  ScopeVerifyResult res;
  EXPECT_EQ(scopes.verify(&p, NOW, &res), SCOPE_EMERGENCY);
  EXPECT_EQ(res.status, SCOPE_VERIFY_OK);
  EXPECT_EQ(res.key, scopes.getConfig(SCOPE_EMERGENCY).pub_keys[0]);
  EXPECT_EQ(res.timestamp, NOW - 3);
  EXPECT_EQ(scopes.getNumVerified(SCOPE_EMERGENCY), 1u);
}

TEST(SecureScopes, NormalPacketsHaveNoProof) {
  Packet p = makeTextMsg("hello");
  EXPECT_FALSE(SecureScopes::hasProof(&p));
  SecureScopes scopes;
  ScopeVerifyResult res;
  EXPECT_EQ(scopes.verify(&p, NOW, &res), SCOPE_NONE);
  EXPECT_EQ(res.status, SCOPE_VERIFY_NO_PROOF);
}

TEST(SecureScopes, RejectsTamperedCiphertext) {
  auto key = makeKey(1);
  SecureScopes scopes;
  scopes.addKey(SCOPE_EMERGENCY, key.pub_key);

  Packet p = signedText(key, SCOPE_EMERGENCY, NOW);
  p.payload[6] ^= 0x01;
  ScopeVerifyResult res;
  EXPECT_EQ(scopes.verify(&p, NOW, &res), SCOPE_NONE);
  EXPECT_EQ(res.status, SCOPE_VERIFY_BAD_SIG);
  EXPECT_EQ(scopes.getNumRejected(SCOPE_EMERGENCY), 1u);
}

TEST(SecureScopes, CopyWithAlteredMACGetsNoPrivileges) {
  auto key = makeKey(1);
  SecureScopes scopes;
  scopes.addKey(SCOPE_EMERGENCY, key.pub_key);

  Packet p = signedText(key, SCOPE_EMERGENCY, NOW);
  ScopeVerifyResult res;
  ASSERT_EQ(scopes.verify(&p, NOW, &res), SCOPE_EMERGENCY);

  p.payload[2] ^= 0x55;   // MAC is not signed: a new packet hash, with the same valid signature
  EXPECT_EQ(scopes.verify(&p, NOW, &res), SCOPE_NONE);
  EXPECT_EQ(res.status, SCOPE_VERIFY_REPLAY);
}

TEST(SecureScopes, RejectsScopeRelabelling) {
  // a key valid for S2 and S0, but packet was signed for S2: relabelling it as S0 must fail
  auto key = makeKey(1);
  SecureScopes scopes;
  scopes.addKey(SCOPE_EMERGENCY, key.pub_key);
  scopes.addKey(SCOPE_PRIVATE, key.pub_key);

  Packet p = signedText(key, SCOPE_PRIVATE, NOW);
  proofOf(p)[65] = SCOPE_EMERGENCY;
  ScopeVerifyResult res;
  EXPECT_EQ(scopes.verify(&p, NOW, &res), SCOPE_NONE);
  EXPECT_EQ(res.status, SCOPE_VERIFY_BAD_SIG);
}

TEST(SecureScopes, RejectsUnknownKeyAndInactiveScope) {
  auto team = makeKey(1);
  auto intruder = makeKey(2);
  SecureScopes scopes;
  ScopeVerifyResult res;

  Packet p = signedText(team, SCOPE_EMERGENCY, NOW);
  EXPECT_EQ(scopes.verify(&p, NOW, &res), SCOPE_NONE);   // S0 has no keys yet
  EXPECT_EQ(res.status, SCOPE_VERIFY_NO_KEY);
  EXPECT_EQ(scopes.getNumUnknown(), 1u);

  scopes.addKey(SCOPE_EMERGENCY, team.pub_key);
  Packet q = signedText(intruder, SCOPE_EMERGENCY, NOW);
  memcpy(&proofOf(q)[66], team.pub_key, 2);   // even with a matching key hint
  EXPECT_EQ(scopes.verify(&q, NOW, &res), SCOPE_NONE);
  EXPECT_EQ(res.status, SCOPE_VERIFY_BAD_SIG);
}

TEST(SecureScopes, MaxAgeOnlyAppliedWhenClockIsSet) {
  auto key = makeKey(1);
  SecureScopes scopes;
  scopes.addKey(SCOPE_EMERGENCY, key.pub_key);
  scopes.setMaxAge(600);
  ScopeVerifyResult res;

  Packet old_pkt = signedText(key, SCOPE_EMERGENCY, NOW - 3600);
  EXPECT_EQ(scopes.verify(&old_pkt, NOW, &res), SCOPE_NONE);
  EXPECT_EQ(res.status, SCOPE_VERIFY_TOO_OLD);
  EXPECT_EQ(scopes.verify(&old_pkt, 12345, &res), SCOPE_EMERGENCY);   // repeater clock not set: don't drop emergency traffic

  Packet fresh = signedText(key, SCOPE_EMERGENCY, NOW - 60, "another message");
  EXPECT_EQ(scopes.verify(&fresh, NOW, &res), SCOPE_EMERGENCY);
}

TEST(SecureScopes, ReservationsOnlyApplyToActiveScopes) {
  SecureScopes scopes;
  EXPECT_EQ(scopes.getConfig(SCOPE_EMERGENCY).airtime_pct, DEFAULT_EMERGENCY_AIRTIME_PCT);
  EXPECT_EQ(scopes.getAirtimeReservePct(SCOPE_EMERGENCY), 0);
  EXPECT_EQ(scopes.getPoolReserve(SCOPE_EMERGENCY), 0);

  auto key = makeKey(1);
  scopes.addKey(SCOPE_EMERGENCY, key.pub_key);
  EXPECT_EQ(scopes.getAirtimeReservePct(SCOPE_EMERGENCY), DEFAULT_EMERGENCY_AIRTIME_PCT);
  EXPECT_EQ(scopes.getPoolReserve(SCOPE_EMERGENCY), DEFAULT_EMERGENCY_POOL_SLOTS);
}

TEST(SecureScopes, ReservationTotalsAreCapped) {
  SecureScopes scopes;
  EXPECT_TRUE(scopes.setAirtimeReserve(SCOPE_ADMIN, MAX_SCOPE_AIRTIME_TOTAL - DEFAULT_EMERGENCY_AIRTIME_PCT));
  EXPECT_FALSE(scopes.setAirtimeReserve(SCOPE_PRIVATE, 1));
  EXPECT_TRUE(scopes.setAirtimeReserve(SCOPE_EMERGENCY, 0));
  EXPECT_TRUE(scopes.setAirtimeReserve(SCOPE_PRIVATE, DEFAULT_EMERGENCY_AIRTIME_PCT));

  EXPECT_FALSE(scopes.setPoolReserve(SCOPE_ADMIN, MAX_SCOPE_POOL_TOTAL));
  EXPECT_TRUE(scopes.setPoolReserve(SCOPE_ADMIN, MAX_SCOPE_POOL_TOTAL - DEFAULT_EMERGENCY_POOL_SLOTS));
}

TEST(SecureScopes, KeyManagement) {
  SecureScopes scopes;
  uint8_t k1[PUB_KEY_SIZE], k2[PUB_KEY_SIZE];
  memset(k1, 0xAB, sizeof(k1));
  memset(k2, 0xAB, sizeof(k2));
  k2[31] = 0x01;

  EXPECT_EQ(scopes.addKey(SCOPE_ADMIN, k1), 1);
  EXPECT_EQ(scopes.addKey(SCOPE_ADMIN, k1), 0);   // duplicate
  EXPECT_EQ(scopes.addKey(SCOPE_ADMIN, k2), 1);
  EXPECT_EQ(scopes.removeKey(SCOPE_ADMIN, k1, 4), -1);   // ambiguous prefix
  EXPECT_EQ(scopes.removeKey(SCOPE_ADMIN, k2, PUB_KEY_SIZE), 1);
  EXPECT_EQ(scopes.getConfig(SCOPE_ADMIN).num_keys, 1);
  EXPECT_EQ(memcmp(scopes.getConfig(SCOPE_ADMIN).pub_keys[0], k1, PUB_KEY_SIZE), 0);

  for (int i = 1; i < MAX_SCOPE_KEYS; i++) {
    k2[0] = i;
    EXPECT_EQ(scopes.addKey(SCOPE_ADMIN, k2), 1);
  }
  k2[0] = 0xEE;
  EXPECT_EQ(scopes.addKey(SCOPE_ADMIN, k2), -1);   // full
}

TEST(SecureScopes, ParseScopeNames) {
  EXPECT_EQ(SecureScopes::parseScope("S0"), SCOPE_EMERGENCY);
  EXPECT_EQ(SecureScopes::parseScope("s1"), SCOPE_ADMIN);
  EXPECT_EQ(SecureScopes::parseScope("2"), SCOPE_PRIVATE);
  EXPECT_EQ(SecureScopes::parseScope("emergency"), SCOPE_EMERGENCY);
  EXPECT_EQ(SecureScopes::parseScope("S3"), -1);
  EXPECT_EQ(SecureScopes::parseScope("S01"), -1);
  EXPECT_EQ(SecureScopes::parseScope("x"), -1);
}

// ---------------------------- packet queue ----------------------------

TEST(ScopedQueue, SecureScopesGoFirst) {
  StaticPoolPacketManager mgr(8);
  Packet* pub = mgr.allocNew();   pub->scope = SCOPE_NONE;
  Packet* s2 = mgr.allocNew();    s2->scope = SCOPE_PRIVATE;
  Packet* s0 = mgr.allocNew();    s0->scope = SCOPE_EMERGENCY;

  mgr.queueOutbound(pub, 0, 0);   // best priority, but public
  mgr.queueOutbound(s2, 5, 0);
  mgr.queueOutbound(s0, 9, 0);

  EXPECT_EQ(mgr.getNextOutbound(10), s0);
  EXPECT_EQ(mgr.getNextOutbound(10), s2);
  EXPECT_EQ(mgr.getNextOutbound(10), pub);
}

TEST(ScopedQueue, MaxScopeFiltersOutPublicTraffic) {
  StaticPoolPacketManager mgr(8);
  Packet* pub = mgr.allocNew();   pub->scope = SCOPE_NONE;
  Packet* raw = mgr.allocNew();   raw->scope = SCOPE_UNCLASSIFIED;
  Packet* s1 = mgr.allocNew();    s1->scope = SCOPE_ADMIN;
  mgr.queueOutbound(pub, 0, 0);
  mgr.queueOutbound(raw, 0, 0);
  mgr.queueOutbound(s1, 0, 100);   // scheduled in future

  EXPECT_EQ(mgr.getOutboundCount(10, SCOPE_PRIVATE), 0);
  EXPECT_EQ(mgr.getNextOutbound(10, SCOPE_PRIVATE), nullptr);
  EXPECT_EQ(mgr.getOutboundCount(200, SCOPE_ADMIN), 1);
  EXPECT_EQ(mgr.getOutboundCount(200, SCOPE_EMERGENCY), 0);
  EXPECT_EQ(mgr.getNextOutbound(200, SCOPE_ADMIN), s1);
  EXPECT_EQ(mgr.getOutboundCount(200), 2);
}

// ---------------------------- dispatcher reservations ----------------------------

class FakeClock : public MillisecondClock {
public:
  unsigned long now = 1000;
  unsigned long getMillis() override { return now; }
};

class FakeRadio : public Radio {
public:
  int num_sent = 0;
  uint8_t last_sent[MAX_TRANS_UNIT];
  bool complete = false;

  int recvRaw(uint8_t* bytes, int sz) override { return 0; }
  uint32_t getEstAirtimeFor(int len_bytes) override { return 100; }
  float packetScore(float snr, int packet_len) override { return 1.0f; }
  bool startSendRaw(const uint8_t* bytes, int len) override {
    memcpy(last_sent, bytes, len);
    num_sent++;
    complete = false;
    return true;
  }
  bool isSendComplete() override { return complete; }
  void onSendFinished() override { }
  bool isInRecvMode() const override { return true; }
};

class TestDispatcher : public Dispatcher {
public:
  uint8_t reserve_pct[NUM_SECURE_SCOPES] = { 10, 0, 0 };
  uint8_t reserve_pool[NUM_SECURE_SCOPES] = { 2, 1, 0 };

  TestDispatcher(Radio& radio, MillisecondClock& ms, PacketManager& mgr) : Dispatcher(radio, ms, mgr) { }

  DispatcherAction onRecvPacket(Packet* pkt) override { return ACTION_RELEASE; }
  unsigned long getDutyCycleWindowMs() const override { return 10000; }   // af=1.0 -> max budget 5000ms
  uint8_t getAirtimeReservePct(uint8_t scope) const override { return reserve_pct[scope]; }
  uint8_t getPoolReserve(uint8_t scope) const override { return reserve_pool[scope]; }
  using Dispatcher::getPoolFloor;
  using Dispatcher::getAirtimeFloor;
};

static Packet* queueFlood(TestDispatcher& d, uint8_t scope, uint8_t tag) {
  Packet* p = d.obtainNewPacket();
  if (p == nullptr) return nullptr;
  p->header = ROUTE_TYPE_FLOOD | (PAYLOAD_TYPE_RAW_CUSTOM << PH_TYPE_SHIFT);
  p->payload[0] = tag;
  p->payload_len = 1;
  p->scope = scope;
  d.sendPacket(p, 1, 0);
  return p;
}

TEST(DispatcherReserve, FloorsAreLayered) {
  FakeClock clock; FakeRadio radio; StaticPoolPacketManager mgr(8);
  TestDispatcher d(radio, clock, mgr);
  d.reserve_pct[SCOPE_ADMIN] = 5;
  d.begin();

  EXPECT_EQ(d.getAirtimeFloor(SCOPE_EMERGENCY), 0u);
  EXPECT_EQ(d.getAirtimeFloor(SCOPE_ADMIN), 500u);      // 10% of 5000
  EXPECT_EQ(d.getAirtimeFloor(SCOPE_PRIVATE), 750u);    // + 5%
  EXPECT_EQ(d.getAirtimeFloor(SCOPE_NONE), 750u);
  EXPECT_EQ(d.getPoolFloor(SCOPE_EMERGENCY), 0);
  EXPECT_EQ(d.getPoolFloor(SCOPE_ADMIN), 2);
  EXPECT_EQ(d.getPoolFloor(SCOPE_NONE), 3);
}

TEST(DispatcherReserve, ReservedAirtimeOnlyForEmergency) {
  FakeClock clock; FakeRadio radio; StaticPoolPacketManager mgr(16);
  TestDispatcher d(radio, clock, mgr);
  d.begin();

  // drain the budget with one long public transmission: 5000 + refill(2300) capped to 5000, - 4600 = 400ms left
  queueFlood(d, SCOPE_NONE, 1);
  clock.now++; d.loop();
  ASSERT_EQ(radio.num_sent, 1);
  clock.now += 4600; radio.complete = true; d.loop();
  ASSERT_LT(d.getRemainingTxBudget(), 500u);   // below the 10% S0 reserve (500ms)

  queueFlood(d, SCOPE_NONE, 2);
  clock.now++; d.loop();
  EXPECT_EQ(radio.num_sent, 1);   // public traffic must not dip into the reserve

  queueFlood(d, SCOPE_EMERGENCY, 3);
  clock.now++; d.loop();
  ASSERT_EQ(radio.num_sent, 2);
  EXPECT_EQ(radio.last_sent[2], 3);   // header, path_len, payload[0]
  clock.now += 10; radio.complete = true; d.loop();

  clock.now++; d.loop();
  EXPECT_EQ(radio.num_sent, 2);   // public still held back
}

TEST(DispatcherReserve, PoolSlotsReservedFromPublicAllocations) {
  FakeClock clock; FakeRadio radio; StaticPoolPacketManager mgr(6);
  TestDispatcher d(radio, clock, mgr);   // pool floor for public = 3
  d.begin();

  int n = 0;
  while (d.obtainNewPacket() != nullptr) n++;
  EXPECT_EQ(n, 3);
  EXPECT_EQ(mgr.getFreeCount(), 3);   // still available for secure scopes (checked in checkRecv())
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
