// Tesla Vehicle Command Protocol primitives.
//
// A tiny, hand-written protobuf codec for the UniversalMessage envelope and an
// explicit command allowlist. Accepting arbitrary protobuf or command input
// would turn the Worker into a generic vehicle-command proxy, so payloads are
// only ever built from the named commands in this file.

import { concatBytes } from "../../bytes";

export const DOMAIN_VEHICLE_SECURITY = 2; // VCSEC: lock, unlock, closures, keys
export const DOMAIN_INFOTAINMENT = 3; // CarServer: climate, charging, media

export type VcpDomain = typeof DOMAIN_VEHICLE_SECURITY | typeof DOMAIN_INFOTAINMENT;

// `Flags` values are bit positions, not masks. Tesla's official client uses
// `1 << FLAG_ENCRYPT_RESPONSE`, where FLAG_ENCRYPT_RESPONSE is enum value 1.
export const FLAG_ENCRYPT_RESPONSE = 1 << 1;

export const MESSAGE_FAULT = {
  NONE: 0,
  BUSY: 1,
  TIMEOUT: 2,
  UNKNOWN_KEY_ID: 3,
  INACTIVE_KEY: 4,
  INVALID_SIGNATURE: 5,
  INVALID_TOKEN_OR_COUNTER: 6,
  INSUFFICIENT_PRIVILEGES: 7,
  INVALID_DOMAINS: 8,
  INVALID_COMMAND: 9,
  DECODING: 10,
  INTERNAL: 11,
  WRONG_PERSONALIZATION: 12,
  BAD_PARAMETER: 13,
  KEYCHAIN_IS_FULL: 14,
  INCORRECT_EPOCH: 15,
  IV_INCORRECT_LENGTH: 16,
  TIME_EXPIRED: 17,
  NOT_PROVISIONED_WITH_IDENTITY: 18,
  COULD_NOT_HASH_METADATA: 19,
  TIME_TO_LIVE_TOO_LONG: 20,
  REMOTE_ACCESS_DISABLED: 21,
  REMOTE_SERVICE_ACCESS_DISABLED: 22,
  COMMAND_REQUIRES_ACCOUNT_CREDENTIALS: 23,
  REQUEST_MTU_EXCEEDED: 24,
  RESPONSE_MTU_EXCEEDED: 25,
  REPEATED_COUNTER: 26,
  INVALID_KEY_HANDLE: 27,
  REQUIRES_RESPONSE_ENCRYPTION: 28,
} as const;

export const OPERATION_STATUS = { OK: 0, WAIT: 1, ERROR: 2 } as const;

type ProtoValue = number | Uint8Array;
export type ProtoField = { number: number; wireType: number; value: ProtoValue };

const EMPTY = new Uint8Array();
const encoder = new TextEncoder();

export function encodeVarint(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new Error("uint32 out of range");
  }
  const bytes: number[] = [];
  let remaining = value;
  do {
    let byte = remaining % 128;
    remaining = Math.floor(remaining / 128);
    if (remaining) byte |= 0x80;
    bytes.push(byte);
  } while (remaining);
  return new Uint8Array(bytes);
}

function encodeTag(fieldNumber: number, wireType: number): Uint8Array {
  return encodeVarint(fieldNumber * 8 + wireType);
}

export function encodeLengthDelimited(fieldNumber: number, value: Uint8Array): Uint8Array {
  return concatBytes(encodeTag(fieldNumber, 2), encodeVarint(value.byteLength), value);
}

export function encodeVarintField(fieldNumber: number, value: number): Uint8Array {
  return concatBytes(encodeTag(fieldNumber, 0), encodeVarint(value));
}

export function encodeFixed32Field(fieldNumber: number, value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new Error("uint32 out of range");
  }
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, true);
  return concatBytes(encodeTag(fieldNumber, 5), bytes);
}

function decodeVarint(data: Uint8Array, start: number): [number, number] {
  let result = 0;
  let multiplier = 1;
  let offset = start;
  // Ten bytes is the protobuf maximum; values beyond uint32 are rejected by
  // callers, but a valid encoder may still sign-extend negative enum values.
  for (let count = 0; count < 10 && offset < data.byteLength; count++) {
    const byte = data[offset++] as number;
    result += (byte & 0x7f) * multiplier;
    if (!(byte & 0x80)) return [result, offset];
    multiplier *= 128;
  }
  throw new Error("malformed protobuf varint");
}

export function parseFields(data: Uint8Array): ProtoField[] {
  const fields: ProtoField[] = [];
  let offset = 0;
  while (offset < data.byteLength) {
    const [tag, afterTag] = decodeVarint(data, offset);
    offset = afterTag;
    const number = Math.floor(tag / 8);
    const wireType = tag & 7;
    if (!number) throw new Error("malformed protobuf field");

    if (wireType === 0) {
      const [value, afterValue] = decodeVarint(data, offset);
      fields.push({ number, wireType, value });
      offset = afterValue;
    } else if (wireType === 1) {
      if (offset + 8 > data.byteLength) throw new Error("truncated protobuf fixed64");
      fields.push({ number, wireType, value: data.slice(offset, offset + 8) });
      offset += 8;
    } else if (wireType === 2) {
      const [length, afterLength] = decodeVarint(data, offset);
      offset = afterLength;
      if (length > data.byteLength - offset) throw new Error("truncated protobuf bytes");
      fields.push({ number, wireType, value: data.slice(offset, offset + length) });
      offset += length;
    } else if (wireType === 5) {
      if (offset + 4 > data.byteLength) throw new Error("truncated protobuf fixed32");
      const value = new DataView(data.buffer, data.byteOffset + offset, 4).getUint32(0, true);
      fields.push({ number, wireType, value });
      offset += 4;
    } else {
      throw new Error("unsupported protobuf wire type");
    }
  }
  return fields;
}

export function bytesField(fields: ProtoField[], number: number): Uint8Array | null {
  const field = fields.find((candidate) => candidate.number === number && candidate.value instanceof Uint8Array);
  return field?.value instanceof Uint8Array ? field.value : null;
}

export function numberField(fields: ProtoField[], number: number): number | null {
  const field = fields.find((candidate) => candidate.number === number && typeof candidate.value === "number");
  return typeof field?.value === "number" ? field.value : null;
}

export type RoutableResponse = {
  operationStatus: number;
  fault: number;
  flags: number;
  toDomain: number | null;
  /** to_destination.routing_address: the client address the reply is for. */
  toRoutingAddress: Uint8Array | null;
  fromDomain: number | null;
  sessionInfo: Uint8Array | null;
  sessionInfoTag: Uint8Array | null;
  commandHmacTag: Uint8Array | null;
  hasResponseEncryptionData: boolean;
  responseNonce: Uint8Array | null;
  responseCounter: number | null;
  responseTag: Uint8Array | null;
  requestUuid: Uint8Array | null;
  uuid: Uint8Array | null;
  payload: Uint8Array | null;
};

function domainField(fields: ProtoField[], number: number): number | null {
  const destinationBytes = bytesField(fields, number);
  if (!destinationBytes) return null;
  return numberField(parseFields(destinationBytes), 1);
}

function routingAddressField(fields: ProtoField[], number: number): Uint8Array | null {
  const destinationBytes = bytesField(fields, number);
  if (!destinationBytes) return null;
  return bytesField(parseFields(destinationBytes), 2);
}

export function parseRoutableResponse(data: Uint8Array): RoutableResponse {
  const fields = parseFields(data);
  const statusBytes = bytesField(fields, 12);
  const status = statusBytes ? parseFields(statusBytes) : [];
  const signatureBytes = bytesField(fields, 13);
  const signature = signatureBytes ? parseFields(signatureBytes) : [];
  const sessionTagBytes = bytesField(signature, 6);
  const sessionTag = sessionTagBytes ? parseFields(sessionTagBytes) : [];
  const hmacBytes = bytesField(signature, 8);
  const hmac = hmacBytes ? parseFields(hmacBytes) : [];
  const responseDataBytes = bytesField(signature, 9);
  const responseData = responseDataBytes ? parseFields(responseDataBytes) : [];
  return {
    operationStatus: numberField(status, 1) ?? OPERATION_STATUS.OK,
    fault: numberField(status, 2) ?? MESSAGE_FAULT.NONE,
    flags: numberField(fields, 52) ?? 0,
    toDomain: domainField(fields, 6),
    toRoutingAddress: routingAddressField(fields, 6),
    fromDomain: domainField(fields, 7),
    sessionInfo: bytesField(fields, 15),
    // session_info_tag is HMAC_Signature_Data { bytes tag = 1 }, not the
    // personalized HMAC shape used for commands (whose tag is field 4).
    sessionInfoTag: bytesField(sessionTag, 1),
    commandHmacTag: bytesField(hmac, 4),
    hasResponseEncryptionData: responseDataBytes !== null,
    responseNonce: bytesField(responseData, 1),
    // Proto3 omits a zero uint32; zero is a valid first response counter.
    responseCounter: responseDataBytes ? (numberField(responseData, 2) ?? 0) : null,
    responseTag: bytesField(responseData, 3),
    requestUuid: bytesField(fields, 50),
    uuid: bytesField(fields, 51),
    payload: bytesField(fields, 10),
  };
}

export type ParsedSessionInfo = {
  counter: number;
  publicKey: Uint8Array;
  epoch: Uint8Array;
  clockTime: number;
  status: number;
};

export function parseSessionInfo(data: Uint8Array): ParsedSessionInfo {
  const fields = parseFields(data);
  const counter = numberField(fields, 1) ?? 0;
  const publicKey = bytesField(fields, 2);
  const epoch = bytesField(fields, 3);
  const clockTime = numberField(fields, 4) ?? 0;
  const status = numberField(fields, 5) ?? 0;
  if (
    !Number.isSafeInteger(counter) ||
    counter < 0 ||
    counter > 0xffff_ffff ||
    !publicKey ||
    publicKey.byteLength !== 65 ||
    publicKey[0] !== 4 ||
    !epoch ||
    epoch.byteLength !== 16 ||
    !Number.isSafeInteger(clockTime) ||
    clockTime < 0 ||
    clockTime > 0xffff_ffff
  ) {
    throw new Error("invalid session info");
  }
  return { counter, publicKey, epoch, clockTime, status };
}

function destinationDomain(domain: number): Uint8Array {
  return encodeVarintField(1, domain);
}

function destinationRoutingAddress(address: Uint8Array): Uint8Array {
  if (address.byteLength !== 16) throw new Error("invalid routing address");
  return encodeLengthDelimited(2, address);
}

export function buildSessionInfoRequest(
  publicKey: Uint8Array,
  routingAddress: Uint8Array,
  uuid: Uint8Array,
  domain: VcpDomain,
): Uint8Array {
  if (publicKey.byteLength !== 65 || publicKey[0] !== 4 || uuid.byteLength !== 16) {
    throw new Error("invalid handshake input");
  }
  return concatBytes(
    encodeLengthDelimited(6, destinationDomain(domain)),
    encodeLengthDelimited(7, destinationRoutingAddress(routingAddress)),
    encodeLengthDelimited(14, encodeLengthDelimited(1, publicKey)),
    encodeLengthDelimited(51, uuid),
  );
}

export function encodeTlv(tag: number, value: Uint8Array): Uint8Array {
  if (!Number.isInteger(tag) || tag < 0 || tag > 255 || value.byteLength > 255) {
    throw new Error("invalid TLV");
  }
  return concatBytes(new Uint8Array([tag, value.byteLength]), value);
}

function uint32BigEndian(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new Error("uint32 out of range");
  }
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, false);
  return bytes;
}

/** Command authentication metadata, byte-for-byte compatible with tescmd and
 * Tesla's metadata hash. TAG_END (0xff) is added by the HMAC caller. */
export function encodeCommandMetadata(input: {
  vin: string;
  epoch: Uint8Array;
  expiresAt: number;
  counter: number;
  domain: VcpDomain;
  flags: number;
}): Uint8Array {
  const parts = [
    encodeTlv(0, new Uint8Array([8])), // SIGNATURE_TYPE_HMAC_PERSONALIZED
    encodeTlv(1, new Uint8Array([input.domain])),
    encodeTlv(2, encoder.encode(input.vin)),
    encodeTlv(3, input.epoch),
    encodeTlv(4, uint32BigEndian(input.expiresAt)),
    encodeTlv(5, uint32BigEndian(input.counter)),
  ];
  // Tesla omits the flags TLV when no flags are set.
  if (input.flags) parts.push(encodeTlv(7, uint32BigEndian(input.flags)));
  return concatBytes(...parts);
}

/** Tesla authenticates SessionInfo with a separate challenge-bound metadata
 * stream. The challenge is the UUID of our handshake request. */
export function encodeSessionInfoMetadata(vin: string, challenge: Uint8Array): Uint8Array {
  if (challenge.byteLength !== 16) throw new Error("invalid challenge");
  return concatBytes(
    encodeTlv(0, new Uint8Array([6])), // SIGNATURE_TYPE_HMAC
    encodeTlv(2, encoder.encode(vin)),
    encodeTlv(6, challenge),
  );
}

/** The request hash a response is bound to, per Tesla's RequestID
 * (internal/authentication/peer.go): SIGNATURE_TYPE_HMAC_PERSONALIZED followed
 * by the command's HMAC tag, which VCSEC truncates to 16 bytes. */
export function responseRequestHash(requestDomain: VcpDomain, requestTag: Uint8Array): Uint8Array {
  if (requestTag.byteLength !== 32) throw new Error("invalid request tag");
  const tag = requestDomain === DOMAIN_VEHICLE_SECURITY ? requestTag.subarray(0, 16) : requestTag;
  return concatBytes(new Uint8Array([8]), tag);
}

/** AES-GCM response metadata from Tesla's vehicle-command protocol. The
 * caller hashes these bytes plus TAG_END (0xff) with SHA-256 to obtain the
 * AES-GCM additional authenticated data. */
export function encodeResponseMetadata(input: {
  vin: string;
  domain: number;
  counter: number;
  flags: number;
  requestHash: Uint8Array;
  fault: number;
}): Uint8Array {
  if (
    !validVIN(input.vin) ||
    !Number.isInteger(input.domain) ||
    input.domain < 0 ||
    input.domain > 255 ||
    (input.requestHash.byteLength !== 17 && input.requestHash.byteLength !== 33) ||
    input.requestHash[0] !== 8
  ) {
    throw new Error("invalid response metadata");
  }
  return concatBytes(
    encodeTlv(0, new Uint8Array([9])), // SIGNATURE_TYPE_AES_GCM_RESPONSE
    encodeTlv(1, new Uint8Array([input.domain])),
    encodeTlv(2, encoder.encode(input.vin)),
    encodeTlv(5, uint32BigEndian(input.counter)),
    // Response flags are always included, including zero.
    encodeTlv(7, uint32BigEndian(input.flags)),
    encodeTlv(8, input.requestHash),
    encodeTlv(9, uint32BigEndian(input.fault)),
  );
}

export function buildSignedCommand(input: {
  publicKey: Uint8Array;
  routingAddress: Uint8Array;
  uuid: Uint8Array;
  payload: Uint8Array;
  epoch: Uint8Array;
  counter: number;
  expiresAt: number;
  tag: Uint8Array;
  domain: VcpDomain;
  flags: number;
}): Uint8Array {
  if (
    input.publicKey.byteLength !== 65 ||
    input.publicKey[0] !== 4 ||
    input.routingAddress.byteLength !== 16 ||
    input.uuid.byteLength !== 16 ||
    input.epoch.byteLength !== 16 ||
    input.tag.byteLength !== 32
  ) {
    throw new Error("invalid signed command input");
  }
  const keyIdentity = encodeLengthDelimited(1, input.publicKey);
  const hmacData = concatBytes(
    encodeLengthDelimited(1, input.epoch),
    encodeVarintField(2, input.counter),
    encodeFixed32Field(3, input.expiresAt),
    encodeLengthDelimited(4, input.tag),
  );
  const signatureData = concatBytes(encodeLengthDelimited(1, keyIdentity), encodeLengthDelimited(8, hmacData));
  return concatBytes(
    encodeLengthDelimited(6, destinationDomain(input.domain)),
    encodeLengthDelimited(7, destinationRoutingAddress(input.routingAddress)),
    encodeLengthDelimited(10, input.payload),
    encodeLengthDelimited(13, signatureData),
    encodeLengthDelimited(51, input.uuid),
    input.flags ? encodeVarintField(52, input.flags) : EMPTY,
  );
}

export function validVIN(value: unknown): value is string {
  return typeof value === "string" && /^[A-HJ-NPR-Z0-9]{17}$/.test(value);
}

// ---------------------------------------------------------------------------
// VCSEC (DOMAIN_VEHICLE_SECURITY)
// ---------------------------------------------------------------------------

// vcsec.proto UnsignedMessage field 2: RKEAction_E. Values match the owner's
// production Python plugin (protocol/payloads.py).
export const RKE_ACTION = { UNLOCK: 0, LOCK: 1 } as const;

/** VCSEC UnsignedMessage { RKEAction_E RKEAction = 2 }. Proto3 omits a zero
 * enum, so the (dangerous, not implemented) unlock would be an empty message;
 * only lock is exposed here. */
export function buildVcsecLockPayload(): Uint8Array {
  return encodeVarintField(2, RKE_ACTION.LOCK);
}

/** Signed commands this Worker can build. Adding a command means adding an
 * entry here with its domain and payload builder, plus test vectors. */
export const SIGNED_COMMANDS = {
  door_lock: {
    domain: DOMAIN_VEHICLE_SECURITY,
    // Matches the Python plugin: VCSEC commands are sent without
    // FLAG_ENCRYPT_RESPONSE and answer with a plaintext FromVCSECMessage.
    flags: 0,
    payload: buildVcsecLockPayload,
  },
} as const satisfies Record<string, { domain: VcpDomain; flags: number; payload: () => Uint8Array }>;

export type SignedCommandName = keyof typeof SIGNED_COMMANDS;

export function isSignedCommandName(value: unknown): value is SignedCommandName {
  return typeof value === "string" && Object.hasOwn(SIGNED_COMMANDS, value);
}

export type VcsecResult =
  | { status: "ok" }
  | { status: "acknowledged" }
  | { status: "wait" }
  | { status: "error"; information: number; genericError: number }
  | { status: "unknown" };

// vcsec.proto SignedMessage_information_E values used for classification.
export const VCSEC_INFORMATION = {
  NONE: 0,
  FAULT_NOT_ON_WHITELIST: 2,
  FAULT_INVALID_TOKEN: 4,
  FAULT_TOKEN_AND_COUNTER_INVALID: 5,
  FAULT_INCORRECT_EPOCH: 15,
  FAULT_TIME_EXPIRED: 17,
} as const;

/** Interpret a VCSEC FromVCSECMessage reply.
 *
 *   FromVCSECMessage { CommandStatus commandStatus = 4; NominalError nominalError = 46; ... }
 *   CommandStatus { OperationStatus_E operationStatus = 1;
 *                   SignedMessage_status signedMessageStatus = 2; }
 *   SignedMessage_status { uint32 counter = 1;
 *                          SignedMessage_information_E signedMessageInformation = 2; }
 *   NominalError { GenericError_E genericError = 1; }
 *
 * An empty reply, or one carrying only other sub-messages (vehicle status,
 * whitelist info), is success. A CommandStatus with OPERATIONSTATUS_OK is only
 * "acknowledged": Tesla's RKE handler (pkg/vehicle/vcsec.go executeRKEAction)
 * treats any CommandStatus as non-terminal and waits for a later reply, so it
 * does not prove the command ran. Anything malformed is "unknown", never
 * success. */
export function parseVcsecResult(payload: Uint8Array): VcsecResult {
  if (!payload.byteLength) return { status: "ok" };
  try {
    const fields = parseFields(payload);
    const nominal = bytesField(fields, 46);
    if (nominal) {
      const genericError = numberField(parseFields(nominal), 1) ?? 0;
      if (genericError !== 0) return { status: "error", information: 0, genericError };
    }
    const commandStatusBytes = bytesField(fields, 4);
    if (!commandStatusBytes) {
      if (fields.some((field) => field.number === 4)) return { status: "unknown" };
      return { status: "ok" };
    }
    const commandStatus = parseFields(commandStatusBytes);
    const operationStatus = numberField(commandStatus, 1) ?? OPERATION_STATUS.OK;
    if (operationStatus === OPERATION_STATUS.OK) return { status: "acknowledged" };
    if (operationStatus === OPERATION_STATUS.WAIT) return { status: "wait" };
    if (operationStatus !== OPERATION_STATUS.ERROR) return { status: "unknown" };
    const signedStatus = bytesField(commandStatus, 2);
    const information = signedStatus ? (numberField(parseFields(signedStatus), 2) ?? 0) : 0;
    return { status: "error", information, genericError: 0 };
  } catch {
    return { status: "unknown" };
  }
}
