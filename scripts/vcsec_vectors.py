"""Generate the VCSEC lock test vectors in test/vcp-vectors.test.ts.

Runs the hermes-tescmd-plugin Python implementation (MIT) with
fixed inputs so the TypeScript signer can be checked byte for byte against it.
The client and vehicle keys are the private scalars 1 and 2 (public points G
and 2G): deliberately worthless, and derived here rather than stored.

Usage (throwaway venv; nothing is installed into the repo):
    python3 -m venv /tmp/vcsec-venv
    /tmp/vcsec-venv/bin/pip install cryptography protobuf httpx fastapi
    /tmp/vcsec-venv/bin/python scripts/vcsec_vectors.py /path/to/hermes-tescmd-plugin/src
"""

import hashlib
import hmac
import json
import os
import struct
import sys

sys.path.insert(0, sys.argv[1])

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from hermes_tescmd_plugin.crypto.ecdh import (  # noqa: E402
    derive_session_key,
    get_uncompressed_public_key,
)
from hermes_tescmd_plugin.protocol import encoder  # noqa: E402
from hermes_tescmd_plugin.protocol.metadata import (  # noqa: E402
    TAG_CHALLENGE,
    TAG_PERSONALIZATION,
    TAG_SIGNATURE_TYPE,
    encode_metadata,
    encode_tlv,
)
from hermes_tescmd_plugin.protocol.payloads import build_command_payload  # noqa: E402
from hermes_tescmd_plugin.protocol.protobuf.messages import Domain  # noqa: E402
from hermes_tescmd_plugin.protocol.signer import (  # noqa: E402
    compute_hmac_tag,
    derive_session_info_key,
    derive_signing_key,
    verify_session_info_tag,
)

VIN = "5YJ3E1EA1NF000001"
client = ec.derive_private_key(1, ec.SECP256R1())
vehicle = ec.derive_private_key(2, ec.SECP256R1())
client_pub = get_uncompressed_public_key(client)
vehicle_pub = get_uncompressed_public_key(vehicle)
epoch = bytes(range(0x00, 0x10))
routing = bytes(range(0x20, 0x30))
uuid_cmd = bytes(range(0x30, 0x40))
uuid_hs = bytes(range(0x40, 0x50))

session_key = derive_session_key(client, vehicle_pub)
assert session_key == derive_session_key(vehicle, client_pub)
signing_key = derive_signing_key(session_key)
si_key = derive_session_info_key(session_key)


def varint(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def ld(field, data):
    return varint(field << 3 | 2) + varint(len(data)) + data


# SessionInfo { counter = 7, publicKey, epoch, clock_time (fixed32) = 1000 }
session_info = (
    varint(1 << 3) + varint(7) + ld(2, vehicle_pub) + ld(3, epoch)
    + varint(4 << 3 | 5) + struct.pack("<I", 1000)
)
meta = (
    encode_tlv(TAG_SIGNATURE_TYPE, bytes([6]))
    + encode_tlv(TAG_PERSONALIZATION, VIN.encode())
    + encode_tlv(TAG_CHALLENGE, uuid_hs)
)
si_tag = hmac.new(si_key, meta + b"\xff" + session_info, hashlib.sha256).digest()
assert verify_session_info_tag(
    si_key, session_info, si_tag, verifier_id=VIN.encode(), challenge=uuid_hs
)

# The plugin draws routing addresses and UUIDs from os.urandom; pin them.
queue = []
os.urandom = lambda n: queue.pop(0)

queue[:] = [routing, uuid_hs]
handshake = encoder.build_session_info_request(
    domain=Domain.DOMAIN_VEHICLE_SECURITY, client_public_key=client_pub
).serialize()

payload = build_command_payload("door_lock", {})
counter = 8
expires_at = 1015
metadata = encode_metadata(
    epoch=epoch,
    expires_at=expires_at,
    counter=counter,
    domain=Domain.DOMAIN_VEHICLE_SECURITY,
    vin=VIN,
)
tag = compute_hmac_tag(signing_key, metadata, payload)
queue[:] = [routing, uuid_cmd]
command = encoder.build_signed_command(
    domain=Domain.DOMAIN_VEHICLE_SECURITY,
    payload=payload,
    client_public_key=client_pub,
    epoch=epoch,
    counter=counter,
    expires_at=expires_at,
    hmac_tag=tag,
).serialize()

print(json.dumps({key: value.hex() for key, value in {
    "client_pub": client_pub,
    "vehicle_pub": vehicle_pub,
    "session_key": session_key,
    "signing_key": signing_key,
    "session_info_key": si_key,
    "session_info": session_info,
    "session_info_tag": si_tag,
    "handshake_request": handshake,
    "lock_payload": payload,
    "lock_metadata": metadata,
    "lock_tag": tag,
    "lock_routable_message": command,
}.items()}, indent=1))
