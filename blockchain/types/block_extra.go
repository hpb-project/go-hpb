package types

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hpb-project/go-hpb/common"
	"github.com/hpb-project/go-hpb/common/hexutil"
	"github.com/hpb-project/go-hpb/common/log"
)

const (
	ExtraVanityLength        = 32
	ExtraSealLength          = 65
	ExtraRealRNDLength       = 32
	ExtraSignedLastRNDLength = 65
	ExtraVersion             = 1 // Version(0) means data before defined ExtraDetail.

)

type ExtraDetail struct {
	Version       uint8                          `json:"version"`
	Vanity        [ExtraVanityLength]byte        `json:"vanity"`
	NodesNum      uint8                          `json:"nodesCount"`
	NodesAddr     common.Addresses               `json:"nodes"`
	RealRND       [ExtraRealRNDLength]byte       `json:"realRandom"`
	SignedLastRND [ExtraSignedLastRNDLength]byte `json:"signedRealRandom"`
	Seal          [ExtraSealLength]byte          `json:"seal"`
	//Warning: if you need add new field, you need modify BytesToExtraDetail/ToBytes/ExceptSealToBytes/MarshalJSON either.
	//And total length can't mod(common.AddressLength)== 0.
}

// only use in rpc output format.
func (h ExtraDetail) MarshalJSON() ([]byte, error) {
	type Detail struct {
		Version       uint8            `json:"version"`
		Vanity        string           `json:"vanity"`
		NodesNum      uint8            `json:"nodesCount"`
		NodesAddr     common.Addresses `json:"nodes"`
		RealRND       hexutil.Bytes    `json:"realRandom"`
		SignedLastRND hexutil.Bytes    `json:"signedRealRandom"`
		Seal          hexutil.Bytes    `json:"seal"`
	}
	var enc Detail
	enc.Version = h.Version

	// change hex to string.
	var tmps = make([]byte, 0)
	for _, b := range h.Vanity {
		if b != 0x0 {
			tmps = append(tmps, b)
		} else {
			break
		}
	}
	enc.Vanity = string(tmps)

	enc.NodesNum = h.NodesNum
	enc.NodesAddr = h.NodesAddr
	enc.RealRND = h.RealRND[:]
	enc.SignedLastRND = h.SignedLastRND[:]
	enc.Seal = h.Seal[:]
	return json.Marshal(&enc)
}

func NewExtraDetail(version uint8) (*ExtraDetail, error) {
	if version != 0 && version != ExtraVersion {
		return nil, errors.New("Invalid version ")
	}
	return &ExtraDetail{Version: version}, nil
}

func BytesToExtraDetail(data []byte) (*ExtraDetail, error) {
	if len(data) < (ExtraVanityLength + ExtraSealLength) {
		return nil, errors.New("Invalid ExtraData, length too short. ")
	}
	detail := new(ExtraDetail)
	remainder := (len(data) - ExtraVanityLength - ExtraSealLength) % common.AddressLength
	offset := 0
	if remainder == 0 {
		// this is extra data before define extraDetail.
		offset = 0
		detail.Version = 0
		copy(detail.Vanity[:], data[:ExtraVanityLength])
		offset += ExtraVanityLength

		detail.NodesNum = uint8((len(data) - ExtraVanityLength - ExtraSealLength) / common.AddressLength)
		if detail.NodesNum > 0 {
			for t := 0; t < int(detail.NodesNum); t++ {
				var addr common.Address
				addr.SetBytes(data[offset : offset+common.AddressLength])
				detail.NodesAddr = append(detail.NodesAddr, addr)
				offset += common.AddressLength
			}
		} else {
			detail.NodesAddr = common.Addresses{}
		}
		copy(detail.Seal[:], data[offset:offset+ExtraSealLength])
		offset += ExtraSealLength

	} else {
		offset = 0
		detail.Version = data[offset]
		offset++
		copy(detail.Vanity[:], data[offset:offset+ExtraVanityLength])
		offset += ExtraVanityLength
		detail.NodesNum = data[offset]
		offset++
		if detail.NodesNum > 0 {
			for t := 0; t < int(detail.NodesNum); t++ {
				var addr common.Address
				addr.SetBytes(data[offset : offset+common.AddressLength])
				detail.NodesAddr = append(detail.NodesAddr, addr)
				offset += common.AddressLength
			}
		} else {
			detail.NodesAddr = common.Addresses{}
		}

		copy(detail.RealRND[:], data[offset:offset+ExtraRealRNDLength])
		offset += ExtraRealRNDLength
		copy(detail.SignedLastRND[:], data[offset:offset+ExtraSignedLastRNDLength])
		offset += ExtraSignedLastRNDLength
		copy(detail.Seal[:], data[offset:offset+ExtraSealLength])
		offset += ExtraSealLength

	}
	if len(data) != offset {
		log.Error("BytesToExtraDetail", "len(data)", len(data), "offset", offset)
		return nil, errors.New("Invalid ExtraData, Unmatched length. ")
	}
	return detail, nil
}

func (this *ExtraDetail) String() string {
	return fmt.Sprintf(`[
version: %d
Vanity:	%s
NodesNum: %d
RealRND: 0x%x
SignedRND: 0x%x
Seal: 0x%x
]`, this.Version, this.Vanity, this.NodesNum, this.RealRND, this.SignedLastRND, this.Seal)
}

func (this *ExtraDetail) ToBytes() []byte {
	if this.Version == 0 {
		var datalen = ExtraVanityLength + ExtraSealLength
		if this.NodesNum > 0 {
			datalen += int(this.NodesNum) * common.AddressLength
		}
		data := make([]byte, datalen)
		offset := 0
		copy(data[:ExtraVanityLength], this.Vanity[:])
		offset += ExtraVanityLength
		if this.NodesNum > 0 {
			for i := 0; i < int(this.NodesNum); i++ {
				copy(data[offset:offset+common.AddressLength], this.NodesAddr[i].Bytes())
				offset += common.AddressLength
			}
		}
		copy(data[offset:offset+ExtraSealLength], this.Seal[:])
		return data
	}
	datalen := 1 + ExtraVanityLength + 1 + ExtraRealRNDLength + ExtraSignedLastRNDLength + ExtraSealLength
	if this.NodesNum > 0 {
		datalen += int(this.NodesNum) * common.AddressLength
	}
	data := make([]byte, datalen)
	offset := 0

	data[offset] = this.Version
	offset++
	copy(data[offset:offset+ExtraVanityLength], this.Vanity[:])
	offset += ExtraVanityLength

	data[offset] = this.NodesNum
	offset++

	if this.NodesNum > 0 {
		for i := 0; i < int(this.NodesNum); i++ {
			copy(data[offset:offset+common.AddressLength], this.NodesAddr[i].Bytes())
			offset += common.AddressLength
		}
	}

	copy(data[offset:offset+ExtraRealRNDLength], this.RealRND[:])
	offset += ExtraRealRNDLength

	copy(data[offset:offset+ExtraSignedLastRNDLength], this.SignedLastRND[:])
	offset += ExtraSignedLastRNDLength

	copy(data[offset:offset+ExtraSealLength], this.Seal[:])
	offset += ExtraSealLength

	return data
}

func (this *ExtraDetail) ExceptSealToBytes() []byte {
	if this.Version == 0 {
		datalen := ExtraVanityLength
		if this.NodesNum > 0 {
			datalen += int(this.NodesNum) * common.AddressLength
		}
		data := make([]byte, datalen)
		offset := 0
		copy(data[:ExtraVanityLength], this.Vanity[:])
		offset += ExtraVanityLength
		if this.NodesNum > 0 {
			for i := 0; i < int(this.NodesNum); i++ {
				copy(data[offset:offset+common.AddressLength], this.NodesAddr[i].Bytes())
				offset += common.AddressLength
			}
		}
		return data
	}
	datalen := 1 + ExtraVanityLength + 1 + ExtraRealRNDLength + ExtraSignedLastRNDLength
	if this.NodesNum > 0 {
		datalen += int(this.NodesNum) * common.AddressLength
	}
	data := make([]byte, datalen)
	offset := 0

	data[offset] = this.Version
	offset++
	copy(data[offset:offset+ExtraVanityLength], this.Vanity[:])
	offset += ExtraVanityLength

	data[offset] = this.NodesNum
	offset++

	if this.NodesNum > 0 {
		for i := 0; i < int(this.NodesNum); i++ {
			copy(data[offset:offset+common.AddressLength], this.NodesAddr[i].Bytes())
			offset += common.AddressLength
		}
	}

	copy(data[offset:offset+ExtraRealRNDLength], this.RealRND[:])
	offset += ExtraRealRNDLength

	copy(data[offset:offset+ExtraSignedLastRNDLength], this.SignedLastRND[:])
	offset += ExtraSignedLastRNDLength

	return data

}

func (this *ExtraDetail) GetVanity() []byte {
	var tmps = make([]byte, 0)
	for _, b := range this.Vanity {
		if b != 0x0 {
			tmps = append(tmps, b)
		} else {
			break
		}
	}
	return tmps
}

func (this *ExtraDetail) SetVanity(vanity []byte) error {
	if len(vanity) >= ExtraVanityLength {
		copy(this.Vanity[:], vanity[0:ExtraVanityLength])
	} else {
		copy(this.Vanity[:len(vanity)], vanity)
	}
	return nil
}

func (this *ExtraDetail) GetSeal() []byte {
	return this.Seal[:]
}

func (this *ExtraDetail) SetSeal(signature []byte) error {
	if len(signature) != ExtraSealLength {
		return errors.New("Invalid signature ")
	}
	copy(this.Seal[:], signature)
	return nil
}

func (this *ExtraDetail) GetRealRND() []byte {
	return this.RealRND[:]
}

func (this *ExtraDetail) SetRealRND(rnd []byte) error {
	if len(rnd) != ExtraRealRNDLength {
		return errors.New("Invalid rnd ")
	}
	copy(this.RealRND[:], rnd)
	return nil
}

func (this *ExtraDetail) GetSignedLastRND() []byte {
	return this.SignedLastRND[:]
}

func (this *ExtraDetail) SetSignedLastRND(signedRnd []byte) error {
	if len(signedRnd) != ExtraSignedLastRNDLength {
		return errors.New("Invalid signedRnd ")
	}
	copy(this.SignedLastRND[:], signedRnd)
	return nil
}

func (this *ExtraDetail) SetNodes(nodes common.Addresses) error {
	for _, addr := range nodes {
		this.NodesAddr = append(this.NodesAddr, addr)
		this.NodesNum++
	}
	return nil
}

func (this *ExtraDetail) GetNodes() common.Addresses {
	return this.NodesAddr
}
