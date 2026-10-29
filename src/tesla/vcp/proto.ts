// A tiny, hand-written protobuf wire codec. Only what the Vehicle Command
// Protocol messages in this directory need: no reflection, no schema, and
// every encoder range-checks its input.

import { concatBytes } from "../../bytes";

type ProtoValue = number | Uint8Array;
export type ProtoField = { number: number; wireType: number; value: ProtoValue };

const encoder = new TextEncoder();

/** Unsigned varint for any safe integer (uint32 and the uint64 values this
 * codec sends, such as epoch-second schedule ids). */
function encodeUnsignedVarint(value: number): Uint8Array {
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

export function encodeVarint(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new Error("uint32 out of range");
  }
  return encodeUnsignedVarint(value);
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

/** uint64 field limited to safe integers (2^53 - 1). */
export function encodeUint64Field(fieldNumber: number, value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("uint64 out of range");
  return concatBytes(encodeTag(fieldNumber, 0), encodeUnsignedVarint(value));
}

/** Non-negative int32. A negative int32 is a ten-byte varint on the wire;
 * nothing this codec sends needs one, so it is refused. */
export function encodeInt32Field(fieldNumber: number, value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0x7fff_ffff) throw new Error("int32 out of range");
  return encodeVarintField(fieldNumber, value);
}

/** sint32: ZigZag-encoded, so small negative numbers stay small. */
export function encodeSint32Field(fieldNumber: number, value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < -0x8000_0000 || value > 0x7fff_ffff) {
    throw new Error("sint32 out of range");
  }
  return encodeVarintField(fieldNumber, value >= 0 ? value * 2 : -value * 2 - 1);
}

export function encodeBoolField(fieldNumber: number, value: boolean): Uint8Array {
  return encodeVarintField(fieldNumber, value ? 1 : 0);
}

export function encodeFixed32Field(fieldNumber: number, value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new Error("uint32 out of range");
  }
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, true);
  return concatBytes(encodeTag(fieldNumber, 5), bytes);
}

/** float (IEEE 754 single precision, rounded as Go's float32() does). */
export function encodeFloatField(fieldNumber: number, value: number): Uint8Array {
  if (!Number.isFinite(value)) throw new Error("float out of range");
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setFloat32(0, value, true);
  return concatBytes(encodeTag(fieldNumber, 5), bytes);
}

export function encodeDoubleField(fieldNumber: number, value: number): Uint8Array {
  if (!Number.isFinite(value)) throw new Error("double out of range");
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setFloat64(0, value, true);
  return concatBytes(encodeTag(fieldNumber, 1), bytes);
}

export function encodeStringField(fieldNumber: number, value: string): Uint8Array {
  return encodeLengthDelimited(fieldNumber, encoder.encode(value));
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
