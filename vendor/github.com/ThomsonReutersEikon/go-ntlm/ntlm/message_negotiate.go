//Copyright 2013 Thomson Reuters Global Resources. BSD License please see License file for more information

package ntlm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type NegotiateMessage struct {
	// sig - 8 bytes
	Signature []byte
	// message type - 4 bytes
	MessageType uint32
	// negotiate flags - 4bytes
	NegotiateFlags uint32
	// If the NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED flag is not set in NegotiateFlags,
	// indicating that no DomainName is supplied in Payload  - then this should have Len 0 / MaxLen 0
	// this contains a domain name
	DomainNameFields *PayloadStruct
	// If the NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED flag is not set in NegotiateFlags,
	// indicating that no WorkstationName is supplied in Payload - then this should have Len 0 / MaxLen 0
	WorkstationFields *PayloadStruct
	//A VERSION structure (8 bytes) that is populated only when the NTLMSSP_NEGOTIATE_VERSION flag is set
	// in the NegotiateFlags field. This structure is used for debugging purposes only.
	Version *VersionStruct
	// payload - variable
	Payload       []byte
	PayloadOffset int
}

// ParseNegotiateMessage decodes and validates the input bytes to create a valid negotiate message
func ParseNegotiateMessage(body []byte) (*NegotiateMessage, error) {
	negotiate := new(NegotiateMessage)
	var err error

	negotiate.Signature = body[0:8]
	if !bytes.Equal(negotiate.Signature, []byte("NTLMSSP\x00")) {
		return negotiate, errors.New("Invalid NTLM message signature")
	}

	negotiate.MessageType = binary.LittleEndian.Uint32(body[8:12])
	if negotiate.MessageType != 1 {
		return negotiate, errors.New("Invalid NTLM message type should be 0x00000001 for negotiate message")
	}

	negotiate.NegotiateFlags = binary.LittleEndian.Uint32(body[12:16])

	negotiate.DomainNameFields, err = ReadOEMStringPayload(16, body)
	if err != nil {
		return nil, err
	} else if NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED.IsSet(negotiate.NegotiateFlags) && negotiate.DomainNameFields.Len == 0 {
		return nil, errors.New("NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED set but no domain supplied for negotiate message")
	}

	negotiate.WorkstationFields, err = ReadOEMStringPayload(24, body)
	if err != nil {
		return nil, err
	} else if NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED.IsSet(negotiate.NegotiateFlags) && negotiate.WorkstationFields.Len == 0 {
		return nil, errors.New("NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED set but no workstation supplied for negotiate message")
	}

	negotiate.Version, err = ReadVersionStruct(body[32:40])
	if err != nil {
		return nil, err
	} else if NTLMSSP_NEGOTIATE_VERSION.IsSet(negotiate.NegotiateFlags) && negotiate.Version.ProductBuild == 0 {
		return nil, errors.New("NTLMSSP_NEGOTIATE_VERSION set but invalid version supplied for negotiate message")
	}

	negotiate.Payload = body[40:]

	return negotiate, nil
}

// Bytes encodes the negotiate message in its on the wire format
func (n *NegotiateMessage) Bytes() []byte {
	messageLen := 8 + 4 + 4 + 8 + 8 + 8
	payloadOffset := uint32(messageLen)

	// Calculate the payload length
	payloadLen := 0
	if n.DomainNameFields != nil {
		payloadLen += int(n.DomainNameFields.Len)
	}
	if n.WorkstationFields != nil {
		payloadLen += int(n.WorkstationFields.Len)
	}

	messageBytes := make([]byte, 0, messageLen+payloadLen)
	buffer := bytes.NewBuffer(messageBytes)

	buffer.Write(n.Signature)

	binary.Write(buffer, binary.LittleEndian, n.MessageType)

	buffer.Write(uint32ToBytes(n.NegotiateFlags))

	if n.DomainNameFields != nil {
		n.DomainNameFields.Offset = payloadOffset
		payloadOffset += uint32(n.DomainNameFields.Len)
		buffer.Write(n.DomainNameFields.Bytes())
	} else {
		p, _ := CreateBytePayload(make([]byte, 0, 0))
		p.Offset = payloadOffset
		buffer.Write(p.Bytes())
	}

	if n.WorkstationFields != nil {
		n.WorkstationFields.Offset = payloadOffset
		payloadOffset += uint32(n.WorkstationFields.Len)
		buffer.Write(n.WorkstationFields.Bytes())
	} else {
		p, _ := CreateBytePayload(make([]byte, 0, 0))
		p.Offset = payloadOffset
		buffer.Write(p.Bytes())
	}

	if n.Version != nil {
		buffer.Write(n.Version.Bytes())
	} else {
		nilVersion := VersionStruct{}
		buffer.Write(nilVersion.Bytes())
	}

	// Write out the payloads
	if n.DomainNameFields != nil {
		buffer.Write(n.DomainNameFields.Payload)
	}

	if n.WorkstationFields != nil {
		buffer.Write(n.WorkstationFields.Payload)
	}

	return buffer.Bytes()
}

func (n *NegotiateMessage) String() string {
	var buffer bytes.Buffer

	buffer.WriteString("Negotiate NTLM Message\n")
	buffer.WriteString(fmt.Sprintf("Payload Offset: %d Length: %d\n", n.getLowestPayloadOffset(), len(n.Payload)))

	buffer.WriteString(fmt.Sprintf("Flags %x\n", n.NegotiateFlags))
	buffer.WriteString(FlagsToString(n.NegotiateFlags))

	if n.DomainNameFields != nil {
		buffer.WriteString(fmt.Sprintf("Domain Name %s\n", n.DomainNameFields.String()))
	}

	if n.WorkstationFields != nil {
		buffer.WriteString(fmt.Sprintf("Workstation Name %s\n", n.WorkstationFields.String()))
	}

	if n.Version != nil {
		buffer.WriteString(fmt.Sprintf("Version: %s\n", n.Version.String()))
	}

	return buffer.String()
}

func (n *NegotiateMessage) getLowestPayloadOffset() int {
	payloadStructs := [...]*PayloadStruct{n.DomainNameFields, n.WorkstationFields}

	// Find the lowest offset value
	lowest := 9999
	for i := range payloadStructs {
		p := payloadStructs[i]
		if p != nil && p.Offset > 0 && int(p.Offset) < lowest {
			lowest = int(p.Offset)
		}
	}

	return lowest
}
