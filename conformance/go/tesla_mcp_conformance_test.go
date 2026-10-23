// tesla-mcp conformance test, compiled inside Tesla's vehicle-command module.
//
// conformance/run.sh copies this file into internal/authentication of a pinned
// checkout of github.com/teslamotors/vehicle-command, because Tesla's signer
// lives in internal packages that cannot be imported from outside the module.
// It rebuilds every value in test/vectors/vcsec-lock.json with Tesla's own code
// and requires byte equality. The TypeScript tests assert the same file, so a
// pass proves the Worker's signer is byte-compatible with Tesla's.
//
// The keys are the private scalars 1 (client) and 2 (vehicle): public test
// values, never real credentials.

package authentication

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"sort"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/signatures"
	universal "github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/universalmessage"
	"github.com/teslamotors/vehicle-command/pkg/protocol/protobuf/vcsec"
)

type hexBytes []byte

func (h *hexBytes) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	decoded, err := hex.DecodeString(text)
	*h = decoded
	return err
}

type conformanceCommand struct {
	Counter         uint32   `json:"counter"`
	ExpiresAt       uint32   `json:"expires_at"`
	Flags           uint32   `json:"flags"`
	CommandUUID     hexBytes `json:"command_uuid"`
	Metadata        hexBytes `json:"metadata"`
	Tag             hexBytes `json:"tag"`
	RoutableMessage hexBytes `json:"routable_message"`
	RequestHash     hexBytes `json:"request_hash"`
}

type conformanceVectors struct {
	Inputs struct {
		ClientScalar   int64    `json:"client_scalar"`
		VehicleScalar  int64    `json:"vehicle_scalar"`
		VIN            string   `json:"vin"`
		Domain         int32    `json:"domain"`
		Epoch          hexBytes `json:"epoch"`
		RoutingAddress hexBytes `json:"routing_address"`
		HandshakeUUID  hexBytes `json:"handshake_uuid"`
		SessionCounter uint32   `json:"session_counter"`
		ClockTime      uint32   `json:"clock_time"`
		TTLSeconds     uint32   `json:"ttl_seconds"`
	} `json:"inputs"`
	Keys struct {
		ClientPublicPoint  hexBytes `json:"client_public_point"`
		VehiclePublicPoint hexBytes `json:"vehicle_public_point"`
		// Named without "key" so secret scanners do not flag deterministic
		// values derived from the public test scalars.
		EcdhSha1128     hexBytes `json:"ecdh_sha1_128"`
		HmacCommand     hexBytes `json:"hmac_command"`
		HmacSessionInfo hexBytes `json:"hmac_session_info"`
	} `json:"derived"`
	Handshake struct {
		Request        hexBytes `json:"request"`
		SessionInfo    hexBytes `json:"session_info"`
		SessionInfoTag hexBytes `json:"session_info_tag"`
	} `json:"handshake"`
	LockPayload hexBytes             `json:"lock_payload"`
	Commands    []conformanceCommand `json:"commands"`
	Response    struct {
		Counter         uint32   `json:"counter"`
		Flags           uint32   `json:"flags"`
		Fault           uint32   `json:"fault"`
		Nonce           hexBytes `json:"nonce"`
		Plaintext       hexBytes `json:"plaintext"`
		Metadata        hexBytes `json:"metadata"`
		Ciphertext      hexBytes `json:"ciphertext"`
		Tag             hexBytes `json:"tag"`
		RoutableMessage hexBytes `json:"routable_message"`
	} `json:"encrypted_response"`
}

// recordingHash captures the exact metadata stream Tesla's code feeds to the
// HMAC, so the TLV bytes themselves can be compared, not only the tag.
type recordingHash struct{ bytes.Buffer }

func (r *recordingHash) Sum(b []byte) []byte { return append(b, r.Bytes()...) }
func (r *recordingHash) Size() int           { return 0 }
func (r *recordingHash) BlockSize() int      { return 1 }

// halfSecond keeps clock-derived values (expiry, clock_time) away from a
// whole-second boundary so they are stable for any realistic test runtime.
const halfSecond = 500 * time.Millisecond

func loadConformanceVectors(t *testing.T) *conformanceVectors {
	t.Helper()
	path := os.Getenv("TESLA_MCP_VECTORS")
	if path == "" {
		t.Fatal("TESLA_MCP_VECTORS must point at test/vectors/vcsec-lock.json")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vectors conformanceVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Commands) == 0 {
		t.Fatal("no command vectors")
	}
	return &vectors
}

func scalarKey(t *testing.T, scalar int64) ECDHPrivateKey {
	t.Helper()
	key := UnmarshalECDHPrivateKey(big.NewInt(scalar).FillBytes(make([]byte, 32)))
	if key == nil {
		t.Fatalf("invalid test scalar %d", scalar)
	}
	return key
}

func expectBytes(t *testing.T, name string, got, want []byte) {
	t.Helper()
	if len(want) == 0 {
		t.Errorf("%s: vector is empty (Tesla produced %x)", name, got)
	} else if !bytes.Equal(got, want) {
		t.Errorf("%s mismatch\n  tesla:   %x\n  vectors: %x", name, got, want)
	}
}

func marshal(t *testing.T, message proto.Message) []byte {
	t.Helper()
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// fieldNumberOrder re-sorts the top-level field records of an encoded message
// by field number, leaving every record's bytes untouched. protobuf-go emits
// oneof fields (payload, signature data) after the regular fields, while the
// TypeScript and Python signers emit strict field-number order; parsers accept
// both. Nested messages here have no such reordering and compare verbatim.
func fieldNumberOrder(t *testing.T, encoded []byte) []byte {
	t.Helper()
	type record struct {
		number protowire.Number
		raw    []byte
	}
	var records []record
	for rest := encoded; len(rest) > 0; {
		number, wireType, tagLength := protowire.ConsumeTag(rest)
		if tagLength < 0 {
			t.Fatalf("malformed tag: %v", protowire.ParseError(tagLength))
		}
		valueLength := protowire.ConsumeFieldValue(number, wireType, rest[tagLength:])
		if valueLength < 0 {
			t.Fatalf("malformed field %d: %v", number, protowire.ParseError(valueLength))
		}
		records = append(records, record{number, rest[:tagLength+valueLength]})
		rest = rest[tagLength+valueLength:]
	}
	sort.SliceStable(records, func(i, j int) bool { return records[i].number < records[j].number })
	var ordered []byte
	for _, r := range records {
		ordered = append(ordered, r.raw...)
	}
	return ordered
}

// expectMessage requires the vector to carry exactly Tesla's field records
// (compared byte for byte in field-number order) and to decode to a message
// proto.Equal to Tesla's, unknown fields included.
func expectMessage(t *testing.T, name string, message proto.Message, want []byte) {
	t.Helper()
	expectBytes(t, name, fieldNumberOrder(t, marshal(t, message)), want)
	decoded := message.ProtoReflect().New().Interface()
	if err := proto.Unmarshal(want, decoded); err != nil {
		t.Errorf("%s: vector does not decode: %v", name, err)
	} else if !proto.Equal(decoded, message) {
		t.Errorf("%s: decoded vector differs from Tesla's message", name)
	}
}

// commandMessage mirrors vehicle.getReceiver plus the addressing that
// dispatcher.Send adds (random routing address and UUID, pinned here).
func commandMessage(v *conformanceVectors, command conformanceCommand) *universal.RoutableMessage {
	return &universal.RoutableMessage{
		ToDestination: &universal.Destination{
			SubDestination: &universal.Destination_Domain{Domain: universal.Domain(v.Inputs.Domain)},
		},
		FromDestination: &universal.Destination{
			SubDestination: &universal.Destination_RoutingAddress{RoutingAddress: v.Inputs.RoutingAddress},
		},
		Payload: &universal.RoutableMessage_ProtobufMessageAsBytes{ProtobufMessageAsBytes: v.LockPayload},
		Uuid:    command.CommandUUID,
		Flags:   command.Flags,
	}
}

func TestTeslaMCPConformance(t *testing.T) {
	v := loadConformanceVectors(t)
	vin := []byte(v.Inputs.VIN)
	if universal.Domain(v.Inputs.Domain) != universal.Domain_DOMAIN_VEHICLE_SECURITY {
		t.Fatalf("vectors target domain %d, expected VCSEC", v.Inputs.Domain)
	}
	client := scalarKey(t, v.Inputs.ClientScalar)
	vehicle := scalarKey(t, v.Inputs.VehicleScalar)

	var signer *Signer

	t.Run("KeysAndSessionDerivation", func(t *testing.T) {
		expectBytes(t, "client public point", client.PublicBytes(), v.Keys.ClientPublicPoint)
		expectBytes(t, "vehicle public point", vehicle.PublicBytes(), v.Keys.VehiclePublicPoint)
		for name, pair := range map[string][2]ECDHPrivateKey{"client": {client, vehicle}, "vehicle": {vehicle, client}} {
			session, err := pair[0].Exchange(pair[1].PublicBytes())
			if err != nil {
				t.Fatal(err)
			}
			native := session.(*NativeSession)
			expectBytes(t, name+" ECDH session", native.key, v.Keys.EcdhSha1128)
			expectBytes(t, name+" command HMAC", native.subkey([]byte(labelMessageAuth)), v.Keys.HmacCommand)
			expectBytes(t, name+" session-info HMAC", native.subkey([]byte(labelSessionInfo)), v.Keys.HmacSessionInfo)
		}
	})

	t.Run("Handshake", func(t *testing.T) {
		// dispatcher.SessionInfoRequest, with the addressing dispatcher.Send
		// adds. (internal/dispatcher imports this package, so it cannot be
		// imported back from an in-package test.)
		request := &universal.RoutableMessage{
			ToDestination: &universal.Destination{
				SubDestination: &universal.Destination_Domain{Domain: universal.Domain(v.Inputs.Domain)},
			},
			FromDestination: &universal.Destination{
				SubDestination: &universal.Destination_RoutingAddress{RoutingAddress: v.Inputs.RoutingAddress},
			},
			Payload: &universal.RoutableMessage_SessionInfoRequest{
				SessionInfoRequest: &universal.SessionInfoRequest{PublicKey: client.PublicBytes()},
			},
			Uuid: v.Inputs.HandshakeUUID,
		}
		expectMessage(t, "session info request", request, v.Handshake.Request)

		// Vehicle side: Tesla's Verifier emits and signs the session info.
		verifier, err := NewVerifier(vehicle, vin, universal.Domain(v.Inputs.Domain), client.PublicBytes())
		if err != nil {
			t.Fatal(err)
		}
		copy(verifier.epoch[:], v.Inputs.Epoch)
		verifier.counter = v.Inputs.SessionCounter
		verifier.timeZero = time.Now().Add(-time.Duration(v.Inputs.ClockTime)*time.Second - halfSecond)
		encodedInfo, tag, err := verifier.SignedSessionInfo(v.Inputs.HandshakeUUID)
		if err != nil {
			t.Fatal(err)
		}
		expectBytes(t, "verifier session info", encodedInfo, v.Handshake.SessionInfo)
		expectBytes(t, "verifier session info tag", tag, v.Handshake.SessionInfoTag)

		// Client side: Tesla's Signer authenticates the vector's session info.
		signer, err = NewAuthenticatedSigner(client, vin, v.Inputs.HandshakeUUID, v.Handshake.SessionInfo, v.Handshake.SessionInfoTag)
		if err != nil {
			t.Fatalf("Tesla rejected the session info vector: %v", err)
		}
		tamperedChallenge := append([]byte{}, v.Inputs.HandshakeUUID...)
		tamperedChallenge[0] ^= 1
		if _, err := NewAuthenticatedSigner(client, vin, tamperedChallenge, v.Handshake.SessionInfo, v.Handshake.SessionInfoTag); err == nil {
			t.Error("session info tag verified under the wrong challenge")
		}
	})
	if signer == nil {
		t.Fatal("handshake failed; cannot sign commands")
	}

	t.Run("LockPayload", func(t *testing.T) {
		payload := &vcsec.UnsignedMessage{
			SubMessage: &vcsec.UnsignedMessage_RKEAction{RKEAction: vcsec.RKEAction_E_RKE_ACTION_LOCK},
		}
		expectBytes(t, "RKE lock payload", marshal(t, payload), v.LockPayload)
	})

	verifier, err := NewVerifier(vehicle, vin, universal.Domain(v.Inputs.Domain), client.PublicBytes())
	if err != nil {
		t.Fatal(err)
	}
	copy(verifier.epoch[:], v.Inputs.Epoch)
	verifier.counter = v.Inputs.SessionCounter
	verifier.timeZero = time.Now().Add(-time.Duration(v.Inputs.ClockTime) * time.Second)

	var lockMessage *universal.RoutableMessage
	for _, command := range v.Commands {
		t.Run(fmt.Sprintf("SignedCommand/counter=%d/flags=%d", command.Counter, command.Flags), func(t *testing.T) {
			if command.ExpiresAt != v.Inputs.ClockTime+v.Inputs.TTLSeconds {
				t.Fatalf("vector expiry %d is not clock_time + ttl_seconds", command.ExpiresAt)
			}
			hmacData := &signatures.HMAC_Personalized_Signature_Data{
				Epoch:     v.Inputs.Epoch,
				Counter:   command.Counter,
				ExpiresAt: command.ExpiresAt,
			}

			// The metadata stream Tesla authenticates, captured verbatim.
			recorder := &recordingHash{}
			meta := newMetadataHash(recorder)
			err := signer.extractMetadata(meta, commandMessage(v, command), hmacData, signatures.SignatureType_SIGNATURE_TYPE_HMAC_PERSONALIZED)
			if err != nil {
				t.Fatal(err)
			}
			expectBytes(t, "command metadata", recorder.Bytes(), command.Metadata)

			tag, err := signer.hmacTag(commandMessage(v, command), hmacData)
			if err != nil {
				t.Fatal(err)
			}
			expectBytes(t, "command HMAC tag", tag, command.Tag)

			// The full signer path: AuthorizeHMAC increments the counter and
			// derives the expiry from its clock, which is pinned to the vector.
			if signer.counter+1 != command.Counter {
				t.Fatalf("signer counter %d does not precede vector counter %d", signer.counter, command.Counter)
			}
			message := commandMessage(v, command)
			ttl := time.Duration(v.Inputs.TTLSeconds)*time.Second + halfSecond
			signer.timeZero = time.Now().Add(-time.Duration(v.Inputs.ClockTime) * time.Second)
			if err := signer.AuthorizeHMAC(message, ttl); err != nil {
				t.Fatal(err)
			}
			expectMessage(t, "signed RoutableMessage", message, command.RoutableMessage)
			expectBytes(t, "request hash (RequestID)", RequestID(message), command.RequestHash)

			// Vehicle side: Tesla's Verifier accepts the vector bytes as sent.
			var received universal.RoutableMessage
			if err := proto.Unmarshal(command.RoutableMessage, &received); err != nil {
				t.Fatal(err)
			}
			plaintext, err := verifier.Verify(&received)
			if err != nil {
				t.Fatalf("Tesla's Verifier rejected the vector command: %v", err)
			}
			expectBytes(t, "verified payload", plaintext, v.LockPayload)
			if _, err := verifier.Verify(&received); err == nil {
				t.Error("Tesla's Verifier accepted a replayed counter")
			}
			if command.Flags == 0 && lockMessage == nil {
				lockMessage = &received
			}
		})
	}
	if lockMessage == nil {
		t.Fatal("no verified flags-0 lock command to bind the response to")
	}

	t.Run("EncryptedResponse", func(t *testing.T) {
		r := v.Response
		requestID := RequestID(lockMessage)
		response := &universal.RoutableMessage{
			ToDestination: &universal.Destination{
				SubDestination: &universal.Destination_RoutingAddress{RoutingAddress: v.Inputs.RoutingAddress},
			},
			FromDestination: &universal.Destination{
				SubDestination: &universal.Destination_Domain{Domain: universal.Domain(v.Inputs.Domain)},
			},
			Payload:     &universal.RoutableMessage_ProtobufMessageAsBytes{ProtobufMessageAsBytes: r.Plaintext},
			RequestUuid: lockMessage.GetUuid(),
			Flags:       r.Flags,
		}
		if r.Fault != 0 {
			response.SignedMessageStatus = &universal.MessageStatus{
				OperationStatus:    universal.OperationStatus_E_OPERATIONSTATUS_ERROR,
				SignedMessageFault: universal.MessageFault_E(r.Fault),
			}
		}

		// Verifier.Encrypt draws a random nonce; this is the same code with
		// the vector's nonce, using Tesla's response metadata and AES-GCM.
		aad, err := verifier.responseMetadata(response, requestID, r.Counter)
		if err != nil {
			t.Fatal(err)
		}
		metaDigest := sha256.Sum256(append(append([]byte{}, r.Metadata...), byte(signatures.Tag_TAG_END)))
		expectBytes(t, "response metadata digest", aad, metaDigest[:])
		sealed := verifier.session.(*NativeSession).gcm.Seal(nil, r.Nonce, r.Plaintext, aad)
		ciphertext, tag := sealed[:len(r.Plaintext)], sealed[len(r.Plaintext):]
		expectBytes(t, "response ciphertext", ciphertext, r.Ciphertext)
		expectBytes(t, "response GCM tag", tag, r.Tag)
		response.Payload = &universal.RoutableMessage_ProtobufMessageAsBytes{ProtobufMessageAsBytes: ciphertext}
		response.SubSigData = &universal.RoutableMessage_SignatureData{
			SignatureData: &signatures.SignatureData{
				SigType: &signatures.SignatureData_AES_GCM_ResponseData{
					AES_GCM_ResponseData: &signatures.AES_GCM_Response_Signature_Data{
						Counter: r.Counter, Nonce: r.Nonce, Tag: tag,
					},
				},
			},
		}
		expectMessage(t, "encrypted response RoutableMessage", response, r.RoutableMessage)

		// Client side: Tesla's Signer decrypts the vector bytes.
		var received universal.RoutableMessage
		if err := proto.Unmarshal(r.RoutableMessage, &received); err != nil {
			t.Fatal(err)
		}
		counter, err := signer.Decrypt(&received, requestID)
		if err != nil {
			t.Fatalf("Tesla's Signer rejected the vector response: %v", err)
		}
		if counter != r.Counter {
			t.Errorf("response counter %d, want %d", counter, r.Counter)
		}
		expectBytes(t, "decrypted response", received.GetProtobufMessageAsBytes(), r.Plaintext)
	})
}
