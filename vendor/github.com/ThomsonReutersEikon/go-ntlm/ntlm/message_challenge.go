//Copyright 2013 Thomson Reuters Global Resources. BSD License please see License file for more information

package ntlm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

type ChallengeMessage struct {
	// sig - 8 bytes
	Signature []byte
	// message type - 4 bytes
	MessageType uint32
	// targetname - 12 bytes
	TargetName *PayloadStruct
	// negotiate flags - 4bytes
	NegotiateFlags uint32
	// server challenge - 8 bytes
	ServerChallenge []byte

	// MS-NLMP and Davenport disagree a little on the next few fields and how optional they are
	// This is what Davenport has to say:
	// As with the Type 1 message, there are a few versions of the Type 2 that have been observed:
	//
	// Version 1 -- The Context, Target Information, and OS Version structure are all omitted. The data block
	// (containing only the contents of the Target Name security buffer) begins at offset 32. This form
	// is seen in older Win9x-based systems, and is roughly documented in the Open Group's ActiveX reference
	// documentation (Section 11.2.3).
	//
	// Version 2 -- The Context and Target Information fields are present, but the OS Version structure is not.
	// The data block begins after the Target Information header, at offset 48. This form is seen in most out-of-box
	// shipping versions of Windows.
	//
	// Version 3 -- The Context, Target Information, and OS Version structure are all present. The data block begins
	// after the OS Version structure, at offset 56. Again, the buffers may be empty (yielding a zero-length data block).
	// This form was introduced in a relatively recent Service Pack, and is seen on currently-patched versions of Windows 2000,
	// Windows XP, and Windows 2003.

	// reserved - 8 bytes (set to 0). This field is also known as 'context' in the davenport documentation
	Reserved []byte

	// targetinfo  - 12 bytes
	TargetInfoPayloadStruct *PayloadStruct
	TargetInfo              *AvPairs

	// version - 8 bytes
	Version *VersionStruct
	// payload - variable
	Payload []byte
}

func ParseChallengeMessage(body []byte) (*ChallengeMessage, error) {
	challenge := new(ChallengeMessage)

	challenge.Signature = body[0:8]
	if !bytes.Equal(challenge.Signature, []byte("NTLMSSP\x00")) {
		return challenge, errors.New("Invalid NTLM message signature")
	}

	challenge.MessageType = binary.LittleEndian.Uint32(body[8:12])
	if challenge.MessageType != 2 {
		return challenge, errors.New("Invalid NTLM message type should be 0x00000002 for challenge message")
	}

	challenge.NegotiateFlags = binary.LittleEndian.Uint32(body[20:24])

	if !NTLMSSP_NEGOTIATE_UNICODE.IsSet(challenge.NegotiateFlags) {
		return challenge, errors.New("Unicode supported not provided by client. Implementation only supports unicode encoding") // Unicode is assumed by this implementation
	}

	var err error

	challenge.TargetName, err = ReadStringPayload(12, body)
	if err != nil {
		return nil, err
	} else if NTLMSSP_REQUEST_TARGET.IsSet(challenge.NegotiateFlags) && challenge.TargetName.Len == 0 {
		return nil, errors.New("NTLMSSP_REQUEST_TARGET set but no target supplied for challenge message")
	}

	challenge.ServerChallenge = body[24:32]

	challenge.Reserved = body[32:40]

	challenge.TargetInfoPayloadStruct, err = ReadBytePayload(40, body)
	if err != nil {
		return nil, err
	} else if NTLMSSP_NEGOTIATE_TARGET_INFO.IsSet(challenge.NegotiateFlags) && challenge.TargetInfoPayloadStruct.Len == 0 {
		return nil, errors.New("NTLMSSP_NEGOTIATE_TARGET_INFO set but no target info supplied for challenge message")
	}
	challenge.TargetInfo = ReadAvPairs(challenge.TargetInfoPayloadStruct.Payload)

	challenge.Version, err = ReadVersionStruct(body[48:56])
	if err != nil {
		return nil, err
	} else if NTLMSSP_NEGOTIATE_VERSION.IsSet(challenge.NegotiateFlags) && challenge.Version.ProductBuild == 0 {
		return nil, errors.New("NTLMSSP_NEGOTIATE_VERSION set but invalid version supplied for challenge message")
	}

	challenge.Payload = body[56:]

	return challenge, nil
}

func (c *ChallengeMessage) Bytes() []byte {
	messageLen := 8 + 4 + 8 + 4 + 8 + 8 + 8 + 8
	payloadOffset := uint32(messageLen)

	// Calculate the payload length
	payloadLen := 0
	if c.TargetName != nil {
		payloadLen += int(c.TargetName.Len)
	}
	if c.TargetInfoPayloadStruct != nil {
		payloadLen += int(c.TargetInfoPayloadStruct.Len)
	}

	messageBytes := make([]byte, 0, messageLen+payloadLen)
	buffer := bytes.NewBuffer(messageBytes)

	buffer.Write(c.Signature)
	binary.Write(buffer, binary.LittleEndian, c.MessageType)

	if c.TargetName != nil {
		c.TargetName.Offset = payloadOffset
		buffer.Write(c.TargetName.Bytes())
		payloadOffset += uint32(c.TargetName.Len)
	} else {
		p, _ := CreateBytePayload(make([]byte, 0, 0))
		p.Offset = payloadOffset
		buffer.Write(p.Bytes())
	}

	binary.Write(buffer, binary.LittleEndian, c.NegotiateFlags)

	buffer.Write(c.ServerChallenge)
	buffer.Write(make([]byte, 8))

	if c.TargetInfoPayloadStruct != nil {
		c.TargetInfoPayloadStruct.Offset = payloadOffset
		buffer.Write(c.TargetInfoPayloadStruct.Bytes())
		payloadOffset += uint32(c.TargetInfoPayloadStruct.Len)
	} else {
		p, _ := CreateBytePayload(make([]byte, 0, 0))
		p.Offset = payloadOffset
		buffer.Write(p.Bytes())
	}

	if c.Version != nil {
		buffer.Write(c.Version.Bytes())
	} else {
		nilVersion := VersionStruct{}
		buffer.Write(nilVersion.Bytes())
	}

	// Write out the payloads
	if c.TargetName != nil {
		buffer.Write(c.TargetName.Payload)
	}
	if c.TargetInfoPayloadStruct != nil {
		buffer.Write(c.TargetInfoPayloadStruct.Payload)
	}

	return buffer.Bytes()
}

func (c *ChallengeMessage) getLowestPayloadOffset() int {
	payloadStructs := [...]*PayloadStruct{c.TargetName, c.TargetInfoPayloadStruct}

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

func (c *ChallengeMessage) String() string {
	var buffer bytes.Buffer

	buffer.WriteString("Challenge NTLM Message")
	buffer.WriteString(fmt.Sprintf("\nPayload Offset: %d Length: %d", c.getLowestPayloadOffset(), len(c.Payload)))
	if c.TargetName != nil {
		buffer.WriteString(fmt.Sprintf("\nTargetName: %s", c.TargetName.String()))
	}
	buffer.WriteString(fmt.Sprintf("\nServerChallenge: %s", hex.EncodeToString(c.ServerChallenge)))
	if c.Version != nil {
		buffer.WriteString(fmt.Sprintf("\nVersion: %s\n", c.Version.String()))
	}
	if c.TargetInfo != nil {
		buffer.WriteString("\nTargetInfo")
		buffer.WriteString(c.TargetInfo.String())
	}
	buffer.WriteString(fmt.Sprintf("\nFlags %x\n", c.NegotiateFlags))
	buffer.WriteString(FlagsToString(c.NegotiateFlags))

	return buffer.String()
}
