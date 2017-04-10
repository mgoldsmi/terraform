//Copyright 2013 Thomson Reuters Global Resources. BSD License please see License file for more information

// Package NTLM implements the interfaces used for interacting with NTLMv1 and NTLMv2.
// To create NTLM v1 or v2 sessions you would use CreateClientSession and create ClientServerSession.
package ntlm

import (
	rc4P "crypto/rc4"
	"errors"
)

type Version int

const (
	Version1 Version = 1
	Version2 Version = 2
)

type Mode struct {
	Integrity       bool
	ReplayDetect    bool
	SequenceDetect  bool
	Confidentiality bool
	Stream          bool
	Identify        bool
	Version         bool
}

var ConnectionOrientedMode Mode = Mode{Stream: true}
var ConnectionlessMode Mode = Mode{Integrity: true, Confidentiality: true, Stream: false}

// Creates an NTLM v1 or v2 client
// mode - This must be ConnectionlessMode or ConnectionOrientedMode depending on what type of NTLM is used
// version - This must be Version1 or Version2 depending on the version of NTLM used
func CreateClientSession(version Version, mode Mode) (n ClientSession, err error) {
	switch version {
	case Version1:
		n = new(V1ClientSession)
	case Version2:
		n = new(V2ClientSession)
	default:
		return nil, errors.New("Unknown NTLM Version, must be 1 or 2")
	}

	n.SetRequestedMode(mode)
	return n, nil
}

type ClientSession interface {
	SetUserInfo(username string, password string, domain string)
	SetMachineName(nbMachineName string)

	SetRequestedMode(mode Mode)
	GetNegotiatedMode() (mode Mode)

	SetConfigFlags(flags uint32) (err error)
	SetMinAuthPolicy(flags uint32)
	SetVersion(ver VersionStruct)

	GenerateNegotiateMessage() (*NegotiateMessage, error)
	ProcessChallengeMessage(*ChallengeMessage) error
	GenerateAuthenticateMessage() (*AuthenticateMessage, error)

	Wrap(message []byte, sequenceNumber uint32) (emessage, mac []byte, err error)
	Unwrap(emessage []byte, expectedMac []byte, sequenceNumber uint32) (message []byte, ok bool, err error)
	Mac(message []byte, sequenceNumber uint32) (mac []byte, err error)
	VerifyMac(message, expectedMac []byte, sequenceNumber uint32) (ok bool, err error)
}

// Creates an NTLM v1 or v2 server
// mode - This must be ConnectionlessMode or ConnectionOrientedMode depending on what type of NTLM is used
// version - This must be Version1 or Version2 depending on the version of NTLM used
func CreateServerSession(version Version, mode Mode) (n ServerSession, err error) {
	switch version {
	case Version1:
		n = new(V1ServerSession)
	case Version2:
		n = new(V2ServerSession)
	default:
		return nil, errors.New("Unknown NTLM Version, must be 1 or 2")
	}

	n.SetRequestedMode(mode)
	return n, nil
}

type ServerSession interface {
	SetUserInfo(username string, password string, domain string)
	GetUserInfo() (string, string, string)

	SetTargetInfo(domainJoined bool, nbMachineName, nbDomainName, dnsMachineName, dnsDomainName, dnsForestName string)

	SetRequestedMode(mode Mode)
	GetNegotiatedMode() (mode Mode)

	SetConfigFlags(flags uint32) (err error)
	SetMinAuthPolicy(flags uint32)
	SetVersion(ver VersionStruct)
	SetMaxLifetime(maxLifeime uint64)

	SetServerChallenge(challege []byte)

	ProcessNegotiateMessage(*NegotiateMessage) error
	GenerateChallengeMessage() (*ChallengeMessage, error)
	ProcessAuthenticateMessage(*AuthenticateMessage) error

	GetSessionData() *SessionData

	Version() int
	Wrap(message []byte, sequenceNumber uint32) (emessage, mac []byte, err error)
	Unwrap(emessage []byte, expectedMac []byte, sequenceNumber uint32) (message []byte, ok bool, err error)
	Mac(message []byte, sequenceNumber uint32) (mac []byte, err error)
	VerifyMac(message, expectedMac []byte, sequenceNumber uint32) (ok bool, err error)
}

// This struct collects NTLM data structures and keys that are used across all types of NTLM requests
type SessionData struct {
	configFlags    uint32
	minAuthPolicy  uint32
	windowsVersion *VersionStruct
	maxLifetime    uint64

	user       string
	password   string
	userDomain string

	domainJoined   bool
	nbMachineName  string
	nbDomainName   string
	dnsMachineName string
	dnsDomainName  string
	dnsForestName  string

	NegotiateFlags uint32

	negotiateMessage    *NegotiateMessage
	challengeMessage    *ChallengeMessage
	authenticateMessage *AuthenticateMessage

	serverChallenge     []byte
	clientChallenge     []byte
	ntChallengeResponse []byte
	lmChallengeResponse []byte

	responseKeyLM             []byte
	responseKeyNT             []byte
	exportedSessionKey        []byte
	encryptedRandomSessionKey []byte
	keyExchangeKey            []byte
	sessionBaseKey            []byte
	mic                       []byte
	timestamp                 []byte

	ClientSigningKey []byte
	ServerSigningKey []byte
	ClientSealingKey []byte
	ServerSealingKey []byte

	clientHandle *rc4P.Cipher
	serverHandle *rc4P.Cipher
}
