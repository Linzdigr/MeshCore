#!/usr/bin/env python3
"""
Secure scope keys (S0 emergency, S1 admin, S2 private).

  Generate a team key pair (the private key file stays with the team, the public key goes on repeaters):
    scope_key.py generate s0_team.key

  Show the public key of a key file:
    scope_key.py show s0_team.key

  Load the private key into a companion (it then signs the messages it floods in that scope):
    scope_key.py set S0 s0_team.key --ble                (BLE, first MeshCore device found)
    scope_key.py set S0 s0_team.key --ble Kiwi           (BLE, device whose name contains 'Kiwi', or its address)
    scope_key.py set S0 s0_team.key --serial /dev/cu.usbmodem1101

  Check / remove, on a companion:
    scope_key.py status --ble
    scope_key.py clear  --ble

  Then on each repeater (serial console, or remotely with meshcli 'cmd'):
    scope key add S0 <public key printed by this script>

Key file: 128 hex chars, the 64-byte private key in MeshCore format (same as 'get prv.key' / private key export).
Companion commands need the 'meshcore' python package (installed with meshcore-cli).
"""

import argparse
import asyncio
import hashlib
import os
import struct
import sys

CMD_SET_SECURE_SCOPE = 0x42
RESP_CODE_SECURE_SCOPE = 0x1D
SCOPE_NAMES = ["emergency", "admin", "private"]

# ------------------------- Ed25519 public key derivation (RFC 8032) -------------------------

_p = 2**255 - 19
_d = -121665 * pow(121666, _p - 2, _p) % _p


def _add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _p
    C = 2 * P[3] * Q[3] * _d % _p
    D = 2 * P[2] * Q[2] % _p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _p, G * H % _p, F * G % _p, E * H % _p)


def _mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _base():
    y = 4 * pow(5, _p - 2, _p) % _p
    x2 = (y * y - 1) * pow(_d * y * y + 1, _p - 2, _p)
    x = pow(x2, (_p + 3) // 8, _p)
    if (x * x - x2) % _p != 0:
        x = x * pow(2, (_p - 1) // 4, _p) % _p
    if x & 1:
        x = _p - x
    return (x, y, 1, x * y % _p)


def derive_pub(prv: bytes) -> bytes:
    """public key from a MeshCore (orlp ed25519) 64-byte private key: first half is the clamped scalar"""
    P = _mul(int.from_bytes(prv[:32], "little"), _base())
    zinv = pow(P[2], _p - 2, _p)
    x, y = P[0] * zinv % _p, P[1] * zinv % _p
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def new_private_key() -> bytes:
    """same as ed25519_create_keypair(): SHA512 of a random seed, clamped"""
    while True:
        h = bytearray(hashlib.sha512(os.urandom(32)).digest())
        h[0] &= 248
        h[31] &= 63
        h[31] |= 64
        prv = bytes(h)
        if derive_pub(prv)[0] not in (0x00, 0xFF):   # reserved prefixes, rejected by firmware
            return prv


def load_key(path: str) -> bytes:
    with open(path) as f:
        text = f.read().strip()
    try:
        prv = bytes.fromhex(text)
    except ValueError:
        sys.exit(f"{path}: not hex")
    if len(prv) != 64:
        sys.exit(f"{path}: expected 128 hex chars (64-byte private key), got {len(text)}")
    return prv


def parse_scope(s: str) -> int:
    s = s.lower()
    if s in ("s0", "s1", "s2"):
        return int(s[1])
    if s in ("0", "1", "2"):
        return int(s)
    if s in SCOPE_NAMES:
        return SCOPE_NAMES.index(s)
    sys.exit(f"unknown scope '{s}', use S0, S1 or S2")

# ------------------------- companion connection -------------------------


async def find_ble(wanted: str) -> str:
    """BLE address of the MeshCore device whose name contains 'wanted' (any MeshCore device if empty)"""
    if wanted and (wanted.count(":") == 5 or (len(wanted) == 36 and wanted.count("-") == 4)):
        return wanted   # already an address (MAC, or macOS UUID)

    from bleak import BleakScanner
    print("scanning BLE for MeshCore devices (5s) ...")
    seen = await BleakScanner.discover(timeout=5, return_adv=True)
    devices = []
    for d, adv in seen.values():
        name = adv.local_name or d.name or ""
        if name.startswith("MeshCore"):
            devices.append((name, d.address))

    matches = [(n, a) for n, a in devices if not wanted or wanted.lower() in n.lower()]
    if not matches:
        found = "\n".join(f"  {n}  ({a})" for n, a in devices) or "  (none: is it on, and not connected to the phone app?)"
        sys.exit(f"no MeshCore device matching '{wanted}'. Found:\n{found}")
    if len(matches) > 1:
        print("several matches, using the first:\n" + "\n".join(f"  {n}  ({a})" for n, a in matches))
    print(f"connecting to {matches[0][0]} ({matches[0][1]})")
    return matches[0][1]


async def run_on_companion(args, payload: bytes):
    try:
        from meshcore import MeshCore, SerialConnection, BLEConnection, TCPConnection, EventType
    except ImportError:
        hint = ""
        pipx_py = os.path.expanduser("~/.local/pipx/venvs/meshcore-cli/bin/python")
        if os.path.exists(pipx_py):
            hint = f"\nmeshcore-cli is installed, use its python:\n  {pipx_py} {' '.join(sys.argv)}"
        sys.exit("needs the 'meshcore' package (pip install meshcore)" + hint)

    if args.serial:
        cx = SerialConnection(args.serial, 115200)
    elif args.tcp:
        host, _, port = args.tcp.partition(":")
        cx = TCPConnection(host, int(port or 5000))
    else:
        cx = BLEConnection(address=await find_ble(args.ble), pin=args.pin)

    mc = MeshCore(cx)
    replies = asyncio.Queue()

    # the meshcore library drops frame types it doesn't know (0x1D), so look at raw frames first
    orig_handle_rx = mc._reader.handle_rx

    async def handle_rx(data):
        if len(data) > 0 and data[0] == RESP_CODE_SECURE_SCOPE:
            await replies.put(bytes(data))
        await orig_handle_rx(data)
    mc._reader.handle_rx = handle_rx

    if await mc.connect() is None:
        sys.exit("could not connect to companion")
    try:
        if payload is not None:
            res = await mc.commands.send(payload, [EventType.OK, EventType.ERROR], timeout=5)
            if res is None or res.type != EventType.OK:
                reason = "" if res is None else f" {res.payload}"
                sys.exit("companion refused the command" + reason +
                         "\n  (ERR 1 = firmware without secure scope support, ERR 6 = bad scope or key)")
            print("OK")

        await mc.commands.send(bytes([CMD_SET_SECURE_SCOPE]), None, timeout=1)   # query
        try:
            frame = await asyncio.wait_for(replies.get(), timeout=5)
        except asyncio.TimeoutError:
            sys.exit("no reply to the query: companion firmware has no secure scope support")
        print_status(frame)
    finally:
        await mc.disconnect()


def print_status(frame: bytes):
    idx = frame[1]
    if idx == 0xFF:
        print("companion: no secure scope (messages are not signed)")
        return
    pub = frame[2:34]
    signed, unsigned = struct.unpack("<II", frame[34:42]) if len(frame) >= 42 else (0, 0)
    print(f"companion: scope S{idx} ({SCOPE_NAMES[idx] if idx < 3 else '?'})")
    print(f"  public key : {pub.hex()}")
    print(f"  since boot : {signed} message(s) signed, {unsigned} too big to sign (sent without priority)")

# ------------------------- main -------------------------


def main():
    ap = argparse.ArgumentParser(description="Secure scope keys: generate, and load into a companion",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="create a new private key file")
    g.add_argument("keyfile")
    s = sub.add_parser("show", help="print the public key of a key file")
    s.add_argument("keyfile")

    conn = argparse.ArgumentParser(add_help=False)
    conn.add_argument("--ble", nargs="?", const="", help="BLE: part of device name, or address (empty: first MeshCore device)")
    conn.add_argument("--pin", help="BLE pairing PIN")
    conn.add_argument("--serial", help="USB serial port, eg. /dev/cu.usbmodem1101")
    conn.add_argument("--tcp", help="host:port")

    st = sub.add_parser("set", parents=[conn], help="load a private key into a companion")
    st.add_argument("scope", help="S0, S1 or S2")
    st.add_argument("keyfile")
    sub.add_parser("status", parents=[conn], help="show the companion's secure scope and counters")
    sub.add_parser("clear", parents=[conn], help="remove the key from the companion")

    args = ap.parse_args()

    if args.cmd == "generate":
        if os.path.exists(args.keyfile):
            sys.exit(f"{args.keyfile} already exists, not overwriting")
        prv = new_private_key()
        fd = os.open(args.keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(prv.hex() + "\n")
        print(f"private key written to {args.keyfile} (keep it secret, it lets anyone sign in the scope)")
        print(f"public key : {derive_pub(prv).hex()}")
        return
    if args.cmd == "show":
        print(f"public key : {derive_pub(load_key(args.keyfile)).hex()}")
        return

    if args.ble is None and not args.serial and not args.tcp:
        ap.error("choose a connection: --ble [name], --serial PORT or --tcp HOST:PORT")

    if args.cmd == "set":
        idx = parse_scope(args.scope)
        prv = load_key(args.keyfile)
        print(f"loading S{idx} key, public key {derive_pub(prv).hex()}")
        payload = bytes([CMD_SET_SECURE_SCOPE, idx]) + prv
    elif args.cmd == "clear":
        payload = bytes([CMD_SET_SECURE_SCOPE, 0xFF])
    else:
        payload = None
    asyncio.run(run_on_companion(args, payload))


if __name__ == "__main__":
    main()
