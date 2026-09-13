package babel

const (
	Magic   = 42
	Version = 2
	Port    = 6696

	headerLen = 4 // Magic(1) Version(1) BodyLength(2)
)

// TLV types, RFC 8966 §4.6.
type TLVType uint8

const (
	TLVPad1         TLVType = 0
	TLVPadN         TLVType = 1
	TLVAckReq       TLVType = 2
	TLVAck          TLVType = 3
	TLVHello        TLVType = 4
	TLVIHU          TLVType = 5
	TLVRouterID     TLVType = 6
	TLVNextHop      TLVType = 7
	TLVUpdate       TLVType = 8
	TLVRouteRequest TLVType = 9
	TLVSeqnoRequest TLVType = 10
)

// Sub-TLV types shared by Hello/IHU (and, per RFC 8966, any TLV), §4.4.
const (
	SubTLVPad1 uint8 = 0
	SubTLVPadN uint8 = 1
	// SubTLVTimestamp carries the RTT extension's timestamps, RFC 9616 §6
	// ("Delay-Based Metric Extension for the Babel Routing Protocol").
	// Confirmed against both the RFC text and BIRD's actual wire encoding,
	// which agree: 3, not the more mnemonic-seeming 4 this was initially
	// miscoded as.
	SubTLVTimestamp uint8 = 3
)

// Address Encodings, RFC 8966 §4.1.4.
const (
	AEWildcard      uint8 = 0
	AEIPv4          uint8 = 1
	AEIPv6          uint8 = 2
	AEIPv6LinkLocal uint8 = 3
	AEIPv4ViaIPv6   uint8 = 4 // RFC 9229: IPv4 prefix with an IPv6 next hop
)

// Special metric value meaning "unreachable" / route retraction, RFC 8966 §4.6.9.
const MetricInfinity uint16 = 0xffff
