package ike

import "testing"

// Every other test in this package names these on both sides of the
// comparison, so what reaches the wire, the number, is pinned by nothing at
// all. Two of them were transposed here once: SET_WINDOW_SIZE carried COOKIE's
// value, which is an interoperability failure no amount of testing against
// ourselves can see. The values are the IANA IKEv2 Notify Message Types
// registry, RFC 7296 section 3.10.1 and RFC 7427 section 4.
func TestNotifyTypesAreRegistryValues(t *testing.T) {
	for name, pair := range map[string]struct {
		got  NotifyType
		want uint16
	}{
		"UNSUPPORTED_CRITICAL_PAYLOAD": {N_UNSUPPORTED_CRITICAL_PAYLOAD, 1},
		"INVALID_SYNTAX":               {N_INVALID_SYNTAX, 7},
		"NO_PROPOSAL_CHOSEN":           {N_NO_PROPOSAL_CHOSEN, 14},
		"INVALID_KE_PAYLOAD":           {N_INVALID_KE_PAYLOAD, 17},
		"AUTHENTICATION_FAILED":        {N_AUTHENTICATION_FAILED, 24},
		"NO_ADDITIONAL_SAS":            {N_NO_ADDITIONAL_SAS, 35},
		"TEMPORARY_FAILURE":            {N_TEMPORARY_FAILURE, 43},
		"CHILD_SA_NOT_FOUND":           {N_CHILD_SA_NOT_FOUND, 44},
		"INITIAL_CONTACT":              {N_INITIAL_CONTACT, 16384},
		"SET_WINDOW_SIZE":              {N_SET_WINDOW_SIZE, 16385},
		"NAT_DETECTION_SOURCE_IP":      {N_NAT_DETECTION_SOURCE_IP, 16388},
		"NAT_DETECTION_DESTINATION_IP": {N_NAT_DETECTION_DESTINATION_IP, 16389},
		"COOKIE":                       {N_COOKIE, 16390},
		"REKEY_SA":                     {N_REKEY_SA, 16393},
		"SIGNATURE_HASH_ALGORITHMS":    {N_SIGNATURE_HASH_ALGORITHMS, 16431},
	} {
		if uint16(pair.got) != pair.want {
			t.Errorf("N_%s is %d on the wire, want %d", name, pair.got, pair.want)
		}
	}
}

// The same argument for everything else that only exists as a number once it
// leaves this process.
func TestWireNumbersAreRegistryValues(t *testing.T) {
	for name, pair := range map[string]struct{ got, want uint16 }{
		"IKE_SA_INIT":     {uint16(IKE_SA_INIT), 34},
		"IKE_AUTH":        {uint16(IKE_AUTH), 35},
		"CREATE_CHILD_SA": {uint16(CREATE_CHILD_SA), 36},
		"INFORMATIONAL":   {uint16(INFORMATIONAL), 37},
		"PayloadSA":       {uint16(PayloadSA), 33},
		"PayloadKE":       {uint16(PayloadKE), 34},
		"PayloadIDi":      {uint16(PayloadIDi), 35},
		"PayloadIDr":      {uint16(PayloadIDr), 36},
		"PayloadCERT":     {uint16(PayloadCERT), 37},
		"PayloadCERTREQ":  {uint16(PayloadCERTREQ), 38},
		"PayloadAUTH":     {uint16(PayloadAUTH), 39},
		"PayloadNonce":    {uint16(PayloadNonce), 40},
		"PayloadN":        {uint16(PayloadN), 41},
		"PayloadD":        {uint16(PayloadD), 42},
		"PayloadV":        {uint16(PayloadV), 43},
		"PayloadTSi":      {uint16(PayloadTSi), 44},
		"PayloadTSr":      {uint16(PayloadTSr), 45},
		"PayloadSK":       {uint16(PayloadSK), 46},
		"AttrKeyLength":   {AttrKeyLength, 14},
	} {
		if pair.got != pair.want {
			t.Errorf("%s is %d on the wire, want %d", name, pair.got, pair.want)
		}
	}
}
