package libkb

import (
	"fmt"
	keybase1 "github.com/keybase/client/go/protocol/keybase1"
)

type SigchainV2Type int

const (
	SigchainV2TypeNone                        SigchainV2Type = 0
	SigchainV2TypeEldest                      SigchainV2Type = 1
	SigchainV2TypeWebServiceBinding           SigchainV2Type = 2
	SigchainV2TypeTrack                       SigchainV2Type = 3
	SigchainV2TypeUntrack                     SigchainV2Type = 4
	SigchainV2TypeRevoke                      SigchainV2Type = 5
	SigchainV2TypeCryptocurrency              SigchainV2Type = 6
	SigchainV2TypeAnnouncement                SigchainV2Type = 7
	SigchainV2TypeDevice                      SigchainV2Type = 8
	SigchainV2TypeWebServiceBindingWithRevoke SigchainV2Type = 9
	SigchainV2TypeCryptocurrencyWithRevoke    SigchainV2Type = 10
	SigchainV2TypeSibkey                      SigchainV2Type = 11
	SigchainV2TypeSubkey                      SigchainV2Type = 12
	SigchainV2TypePGPUpdate                   SigchainV2Type = 13
)

// OuterLinkV2 is the second version of Keybase sigchain signatures.
type OuterLinkV2 struct {
	_struct  bool           `codec:",toarray"`
	version  int            `codec:"version"`
	seqno    Seqno          `codec:"seqno"`
	prev     LinkID         `codec:"prev"`
	body     []byte         `codec:"body"`
	linkType SigchainV2Type `codec:"type"`
}

func (o OuterLinkV2) Encode() ([]byte, error) {
	return MsgpackEncode(o)
}

func DecodeOuterLinkV2(armored string) (*OuterLinkV2, keybase1.KID, error) {
	payload, kid, _, err := SigExtractPayloadAndKID(armored)
	if err != nil {
		return nil, kid, err
	}
	var ret OuterLinkV2
	err = MsgpackDecode(&ret, payload)
	if err != nil {
		return nil, kid, err
	}
	return &ret, kid, nil
}

func SigchainV2TypeFromV1TypeAndRevocations(s string, hasRevocations bool) (SigchainV2Type, error) {
	switch s {
	case "eldest":
		return SigchainV2TypeEldest, nil
	case "web_service_binding":
		if hasRevocations {
			return SigchainV2TypeWebServiceBindingWithRevoke, nil
		}
		return SigchainV2TypeWebServiceBinding, nil
	case "track":
		return SigchainV2TypeTrack, nil
	case "untrack":
		return SigchainV2TypeUntrack, nil
	case "revoke":
		return SigchainV2TypeRevoke, nil
	case "cryptocurrency":
		if hasRevocations {
			return SigchainV2TypeCryptocurrencyWithRevoke, nil
		}
		return SigchainV2TypeCryptocurrency, nil
	case "announcement":
		return SigchainV2TypeAnnouncement, nil
	case "device":
		return SigchainV2TypeDevice, nil
	case "sibkey":
		return SigchainV2TypeSibkey, nil
	case "subkey":
		return SigchainV2TypeSubkey, nil
	case "pgp_update":
		return SigchainV2TypePGPUpdate, nil
	default:
		return SigchainV2TypeNone, ChainLinkError{fmt.Sprintf("Unknow sig v1 type: %s", s)}
	}
}
