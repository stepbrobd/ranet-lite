// Package ike is an IKEv2 initiator and responder in the minimal shape
// [RFC 7815] describes, negotiating a tunnel-mode Child SA that
// [github.com/NickCao/ranet-lite/esp] then carries. It offers one set of
// transforms and no others: raw Ed25519 public key authentication ([RFC 7427]
// Digital Signature with an ASN1_DN identity), X25519, AES-GCM or
// ChaCha20-Poly1305, UDP encapsulation forced on, and 0.0.0.0/0 with ::/0 as
// the traffic selectors. It interoperates with a strongSwan responder
// configured the same way.
//
// Certificates, EAP, MOBIKE and the legacy transforms, CBC ciphers, MODP
// groups and SHA-1 or MD5, are left out rather than unfinished, and a peer
// proposing only those is refused.
//
// # What a caller uses
//
// Both roles run over a [github.com/NickCao/ranet-lite/transport] hub, which
// the caller binds and hands in, because IKE and the ESP it negotiates share
// one UDP port.
//
//   - Dialing. [Initiate] or [InitiateContext] take a [PeerConfig] naming both
//     identities and both keys, and return a [Session] holding the negotiated
//     [ChildSA]. [Session.Run] then drives that SA for its lifetime, answering
//     the peer's liveness checks and deletes and rekeying before a key
//     expires. [Session.SetChildHandler] and [Session.SetChildRetireHandler]
//     are where a rekey hands the caller the replacement keys and takes the
//     old SPI back, so the caller's dataplane swaps without dropping a packet.
//   - Answering. [NewResponder] takes a [ResponderConfig] whose Lookup
//     resolves an initiator's asserted identity to the key that has to verify
//     it, and [Responder.Serve] calls back with a [Session] and an [Accepted]
//     for each peer that authenticates. One responder serves every peer, and
//     holds no state for one until IDi is verified.
//   - Timing. [Crypto] is the cap.crypto capability, carrying yaml, json and
//     toml tags and the replay window alongside the rekey intervals, since a
//     session captures all of them when it is set up. Its durations come from
//     [github.com/NickCao/ranet-lite/schema], and the Default constants below
//     give the values an absent block runs with.
//
// The message, payload and transform codecs are exported beside those, so a
// caller can build or read one exchange without driving a session. [RFC 7296]
// numbers every constant here, and each declaration names its section.
//
// [RFC 7296]: https://www.rfc-editor.org/rfc/rfc7296
// [RFC 7427]: https://www.rfc-editor.org/rfc/rfc7427
// [RFC 7815]: https://www.rfc-editor.org/rfc/rfc7815
package ike

// Exchange types, RFC 7296 §3.1.
type ExchangeType uint8

const (
	IKE_SA_INIT     ExchangeType = 34
	IKE_AUTH        ExchangeType = 35
	CREATE_CHILD_SA ExchangeType = 36
	INFORMATIONAL   ExchangeType = 37
)

// IKE header flags, RFC 7296 §3.1.
const (
	FlagInitiator uint8 = 1 << 3
	FlagVersion   uint8 = 1 << 4
	FlagResponse  uint8 = 1 << 5
)

// Payload types, RFC 7296 §3.2.
type PayloadType uint8

const (
	PayloadNone    PayloadType = 0
	PayloadSA      PayloadType = 33
	PayloadKE      PayloadType = 34
	PayloadIDi     PayloadType = 35
	PayloadIDr     PayloadType = 36
	PayloadCERT    PayloadType = 37
	PayloadCERTREQ PayloadType = 38
	PayloadAUTH    PayloadType = 39
	PayloadNonce   PayloadType = 40
	PayloadN       PayloadType = 41
	PayloadD       PayloadType = 42
	PayloadV       PayloadType = 43
	PayloadTSi     PayloadType = 44
	PayloadTSr     PayloadType = 45
	PayloadSK      PayloadType = 46
	PayloadCP      PayloadType = 47
	PayloadEAP     PayloadType = 48
)

// Protocol IDs, RFC 7296 §3.3.1.
type ProtocolID uint8

const (
	ProtoIKE ProtocolID = 1
	ProtoAH  ProtocolID = 2
	ProtoESP ProtocolID = 3
)

// Transform types, RFC 7296 §3.3.2.
type TransformType uint8

const (
	TransEncr  TransformType = 1
	TransPRF   TransformType = 2
	TransInteg TransformType = 3
	TransDH    TransformType = 4
	TransESN   TransformType = 5
)

// Transform IDs we actually use — modern only. RFC 8247 / IANA IKEv2 registry.
const (
	// Encryption (Transform Type 1)
	ENCR_AES_GCM_16        uint16 = 20 // AEAD, 16-byte ICV, key length via attribute
	ENCR_CHACHA20_POLY1305 uint16 = 28 // AEAD, fixed 32-byte key + 4-byte salt

	// PRF (Transform Type 2)
	PRF_HMAC_SHA2_256 uint16 = 5
	PRF_HMAC_SHA2_384 uint16 = 6

	// Integrity (Transform Type 3). An AEAD cipher needs none, and RFC 7296
	// section 3.3.2's registry gives algorithm 0 the name NONE, so a peer may
	// say so either by omitting the transform or by offering that.
	INTEG_NONE uint16 = 0

	// DH groups (Transform Type 4)
	DH_ECP_256    uint16 = 19
	DH_ECP_384    uint16 = 20
	DH_CURVE25519 uint16 = 31

	// ESN (Transform Type 5)
	ESN_NO  uint16 = 0
	ESN_YES uint16 = 1
)

// Transform attribute types, RFC 7296 §3.3.5.
const (
	AttrKeyLength uint16 = 14 // TV format, value in bits
)

// Notify message types we care about, RFC 7296 §3.10.1.
type NotifyType uint16

const (
	N_NAT_DETECTION_SOURCE_IP      NotifyType = 16388
	N_NAT_DETECTION_DESTINATION_IP NotifyType = 16389

	N_UNSUPPORTED_CRITICAL_PAYLOAD NotifyType = 1
	N_INVALID_SYNTAX               NotifyType = 7
	N_AUTHENTICATION_FAILED        NotifyType = 24
	N_NO_PROPOSAL_CHOSEN           NotifyType = 14
	N_INVALID_KE_PAYLOAD           NotifyType = 17
	N_NO_ADDITIONAL_SAS            NotifyType = 35
	N_TEMPORARY_FAILURE            NotifyType = 43
	N_CHILD_SA_NOT_FOUND           NotifyType = 44
	N_REKEY_SA                     NotifyType = 16393
	N_INITIAL_CONTACT              NotifyType = 16384
	N_SET_WINDOW_SIZE              NotifyType = 16385
	N_COOKIE                       NotifyType = 16390

	// N_SIGNATURE_HASH_ALGORITHMS, RFC 7427 §4: without this in IKE_SA_INIT,
	// strongSwan assumes the peer only understands the classic RSA/ECDSA
	// AUTH methods and signs its own IKE_AUTH with those instead of RFC 7427
	// Digital Signature — which fails outright for an Ed25519 key (charon's
	// sign_classic() only handles KEY_RSA/KEY_ECDSA).
	N_SIGNATURE_HASH_ALGORITHMS NotifyType = 16431
)

// Hash algorithm IDs for the SIGNATURE_HASH_ALGORITHMS notify data (RFC 7427
// §3). HashIdentity is RFC 8420's addition for signature algorithms that hash
// the message themselves, which is how EdDSA is advertised.
const (
	HashSHA2_256 uint16 = 2
	HashSHA2_384 uint16 = 3
	HashIdentity uint16 = 5
)

// Authentication methods, RFC 7296 §3.8, extended by RFC 7427.
const (
	AuthDigitalSignature uint8 = 14 // RFC 7427 "Digital Signature"
)

// ID types, RFC 7296 §3.5.
const (
	ID_DER_ASN1_DN uint8 = 9
)

// ASN.1 OID for Ed25519 (RFC 8410), used both as the RFC 7427 signature
// AlgorithmIdentifier and inside the SubjectPublicKeyInfo strongSwan expects.
var OIDEd25519 = []byte{0x06, 0x03, 0x2b, 0x65, 0x70} // OID 1.3.101.112

const NonESPMarkerLen = 4

const (
	IKEPortInitial = 500
	IKEPortNATT    = 4500
)
