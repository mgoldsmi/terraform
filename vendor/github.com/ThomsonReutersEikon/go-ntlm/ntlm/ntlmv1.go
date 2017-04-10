//Copyright 2013 Thomson Reuters Global Resources. BSD License please see License file for more information

package ntlm

import (
	"bytes"
	rc4P "crypto/rc4"
	"errors"
	"fmt"
	"log"
	"strings"
)

/*******************************
 Shared Session Data and Methods
*******************************/

type V1Session struct {
	SessionData
}

func (n *V1Session) SetUserInfo(username string, password string, domain string) {
	n.user = username
	n.password = password
	n.userDomain = domain
}

func (n *V1Session) GetUserInfo() (string, string, string) {
	return n.user, n.password, n.userDomain
}

// SetRequestedMode sets the client configuration flags to a default bitmask to enable the features reqested
// The default bitmask may be overridden by setting the configuratation flags directly by calling SetConfigFlags
func (n *V1Session) SetRequestedMode(mode Mode) {
	flags := uint32(0)

	if mode.Integrity || mode.ReplayDetect || mode.SequenceDetect {
		flags = NTLMSSP_NEGOTIATE_SIGN.Set(flags)
	}

	if mode.Confidentiality {
		flags = NTLMSSP_NEGOTIATE_SEAL.Set(flags)
		flags = NTLMSSP_NEGOTIATE_KEY_EXCH.Set(flags)
		flags = NTLMSSP_NEGOTIATE_LM_KEY.Set(flags)
		flags = NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.Set(flags)
		flags = NTLMSSP_NEGOTIATE_56.Set(flags)
		flags = NTLMSSP_NEGOTIATE_128.Set(flags)
	}

	if !mode.Stream {
		flags = NTLMSSP_NEGOTIATE_DATAGRAM.Set(flags)
		flags = NTLMSSP_NEGOTIATE_KEY_EXCH.Set(flags)
	}

	if mode.Identify {
		flags = NTLMSSP_NEGOTIATE_IDENTIFY.Set(flags)
	}

	if mode.Version {
		flags = NTLMSSP_NEGOTIATE_VERSION.Set(flags)
	}

	n.SetConfigFlags(flags)
}

// GetMode may be used to summarise which modes have been negotiated. It should only be called after the session has been negotiated
func (n *V1Session) GetNegotiatedMode() (mode Mode) {

	mode.Integrity = NTLMSSP_NEGOTIATE_SIGN.IsSet(n.NegotiateFlags)
	mode.ReplayDetect = NTLMSSP_NEGOTIATE_SIGN.IsSet(n.NegotiateFlags)
	mode.SequenceDetect = NTLMSSP_NEGOTIATE_SIGN.IsSet(n.NegotiateFlags)
	mode.Confidentiality = NTLMSSP_NEGOTIATE_SEAL.IsSet(n.NegotiateFlags)
	mode.Stream = !NTLMSSP_NEGOTIATE_DATAGRAM.IsSet(n.NegotiateFlags)
	mode.Identify = NTLMSSP_NEGOTIATE_IDENTIFY.IsSet(n.NegotiateFlags)

	return mode
}

// SetConfigFlags sets the client/server configuration flags (depending upon the session type) used to negotiate the NTLM session
func (n *V1Session) SetConfigFlags(flags uint32) (err error) {

	if err = n.CheckNegotiateFlags(flags); err != nil {
		return err
	}

	n.configFlags = flags
	return nil
}

// InitialNegotiateFlags returns the desired set of negotiated flags. They are used to start the session negotiation process for both connection oriented and
// connectionless modes
func (n *V1Session) InitialNegotiateFlags() (flags uint32) {

	// 3.1.5.1.1: The client sets the following configuration flags in the NegotiateFlags field of the NEGOTIATE_MESSAGE
	flags = uint32(0)
	flags = NTLMSSP_REQUEST_TARGET.Set(flags)
	flags = NTLMSSP_NEGOTIATE_NTLM.Set(flags)
	flags = NTLMSSP_NEGOTIATE_ALWAYS_SIGN.Set(flags)
	flags = NTLMSSP_NEGOTIATE_UNICODE.Set(flags)

	// In addition, the client sets the flags specified by the application in the NegotiateFlags field in addition to the initialized flags
	flags |= n.configFlags

	// If LM authentication is not being used, then the client sets the following configuration flag in the NegotiateFlags field of the NEGOTIATE_MESSAGE
	if !NTLMSSP_NEGOTIATE_LM_KEY.IsSet(flags) {
		NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.Set(flags)
	}

	return flags
}

// AcceptNegotiateFlags reviews the requested flags and produces a set of agreed flags that can be supported by the client & server
func (n *V1Session) AcceptNegotiateFlags(reqFlags uint32) (flags uint32, err error) {

	flags = uint32(0)

	// Set only the supported flags that were requested in the CHALLENGE_MESSAGE.NegotiateFlags
	flags |= reqFlags & n.GetSupportedNegotiateFlags()

	flags = NTLMSSP_NEGOTIATE_NTLM.Set(flags)
	flags = NTLMSSP_NEGOTIATE_ALWAYS_SIGN.Set(flags)

	if NTLMSSP_NEGOTIATE_UNICODE.IsSet(reqFlags) {
		flags = NTLMSSP_NEGOTIATE_UNICODE.Set(flags)
	} else if NTLM_NEGOTIATE_OEM.IsSet(reqFlags) {
		// OEM mode not supported. Generate error
		// NTLMSSP_NEGOTIATE_OEM.Set(flags)
		return flags, errors.New("OEM encoding not supported")
	}

	if NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.IsSet(reqFlags) {
		flags = NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.Set(flags)
	} else if NTLMSSP_NEGOTIATE_LM_KEY.IsSet(reqFlags) {
		flags = NTLMSSP_NEGOTIATE_LM_KEY.Set(flags)
	}

	return flags, nil
}

// CheckNegotiateFlags checks that the flags provided are supported and meet the minimum security requirements
func (n *V1Session) CheckNegotiateFlags(flags uint32) (err error) {

	// Check that all flags are supported
	if unsupportedFlags := flags &^ n.GetSupportedNegotiateFlags(); unsupportedFlags != 0 {
		err := fmt.Errorf("Config flags contain unsupported flags (%08X)", unsupportedFlags)
		return err
	}

	// Check that minimum security requirements are met
	if (flags & n.minAuthPolicy) != n.minAuthPolicy {
		err := fmt.Errorf("Config flags do not meet minimum authentication policy")
		return err
	}

	return nil
}

// GetSupportedNegotiateFlags returns the full set of NTLM flags supported by this library
func (n *V1Session) GetSupportedNegotiateFlags() (flags uint32) {
	flags = uint32(0)
	flags = NTLMSSP_NEGOTIATE_56.Set(flags)
	flags = NTLMSSP_NEGOTIATE_KEY_EXCH.Set(flags)
	flags = NTLMSSP_NEGOTIATE_128.Set(flags)
	flags = NTLMSSP_NEGOTIATE_VERSION.Set(flags)
	flags = NTLMSSP_NEGOTIATE_TARGET_INFO.Set(flags)
	flags = NTLMSSP_REQUEST_NON_NT_SESSION_KEY.Set(flags)
	flags = NTLMSSP_NEGOTIATE_IDENTIFY.Set(flags)
	flags = NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.Set(flags)
	flags = NTLMSSP_TARGET_TYPE_SERVER.Set(flags)
	flags = NTLMSSP_TARGET_TYPE_DOMAIN.Set(flags)
	flags = NTLMSSP_NEGOTIATE_ALWAYS_SIGN.Set(flags)
	flags = NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED.Set(flags)
	flags = NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED.Set(flags)
	//NTLMSSP_ANONYMOUS not supported
	flags = NTLMSSP_NEGOTIATE_NTLM.Set(flags)
	flags = NTLMSSP_NEGOTIATE_LM_KEY.Set(flags)
	flags = NTLMSSP_NEGOTIATE_DATAGRAM.Set(flags)
	flags = NTLMSSP_NEGOTIATE_SEAL.Set(flags)
	flags = NTLMSSP_NEGOTIATE_SIGN.Set(flags)
	flags = NTLMSSP_REQUEST_TARGET.Set(flags)
	//NTLM_NEGOTIATE_OEM not supported
	flags = NTLMSSP_NEGOTIATE_UNICODE.Set(flags)
	return flags
}

// Set the negotiate flags that represent the minimum authentication policy of the client or server. This is designed to emulate
// the function of the HKEY_LOCAL_MACHINE\System\CurrentControlSet\control\LSA\MSV1_0 registry key.
// See https://support.microsoft.com/en-us/help/239869/how-to-enable-ntlm-2-authentication
func (n *V1Session) SetMinAuthPolicy(flags uint32) {
	n.minAuthPolicy = flags
}

func (n *V1Session) SetMaxLifetime(maxLifetime uint64) {
	log.Printf("WARN: Call to SetMaxLifetime() ignored as lifetime check is NTLMv2 functionality")
}

func (n *V1Session) Version() int {
	return 1
}

// Sets the Windows Version information to be passed between the client and server during authentication
func (n *V1Session) SetVersion(version VersionStruct) {
	n.windowsVersion = &version
}

func (n *V1Session) fetchResponseKeys() (err error) {
	// Usually at this point we'd go out to Active Directory and get these keys
	// Here we are assuming we have the information locally
	n.responseKeyLM, err = lmowfv1(n.password)
	if err != nil {
		return err
	}
	n.responseKeyNT = ntowfv1(n.password)
	return
}

func (n *V1Session) computeExpectedResponses() (err error) {
	if NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.IsSet(n.NegotiateFlags) {
		n.ntChallengeResponse, err = desL(n.responseKeyNT, md5(concat(n.serverChallenge, n.clientChallenge))[0:8])
		if err != nil {
			return err
		}
		n.lmChallengeResponse = concat(n.clientChallenge, make([]byte, 16))
	} else {
		n.ntChallengeResponse, err = desL(n.responseKeyNT, n.serverChallenge)
		if err != nil {
			return err
		}
		// NoLMResponseNTLMv1: A Boolean setting that controls using the NTLM response for the LM
		// response to the server challenge when NTLMv1 authentication is used.<30>
		// <30> Section 3.1.1.1: The default value of this state variable is TRUE. Windows NT Server 4.0 SP3
		// does not support providing NTLM instead of LM responses.
		noLmResponseNtlmV1 := false
		if noLmResponseNtlmV1 {
			n.lmChallengeResponse = n.ntChallengeResponse
		} else {
			n.lmChallengeResponse, err = desL(n.responseKeyLM, n.serverChallenge)
			if err != nil {
				return err
			}
		}
	}
	n.sessionBaseKey = md4(n.responseKeyNT)

	return nil
}

func (n *V1Session) computeKeyExchangeKey() (err error) {
	if NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.IsSet(n.NegotiateFlags) {
		n.keyExchangeKey = hmacMd5(n.sessionBaseKey, concat(n.serverChallenge, n.lmChallengeResponse[0:8]))
	} else {
		n.keyExchangeKey, err = kxKey(n.NegotiateFlags, n.sessionBaseKey, n.lmChallengeResponse, n.serverChallenge, n.responseKeyLM)
	}
	return
}

func (n *V1Session) calculateKeys(ntlmRevisionCurrent uint8) (err error) {
	n.ClientSigningKey = signKey(n.NegotiateFlags, n.exportedSessionKey, "Client")
	n.ServerSigningKey = signKey(n.NegotiateFlags, n.exportedSessionKey, "Server")
	n.ClientSealingKey = sealKey(n.NegotiateFlags, n.exportedSessionKey, "Client", ntlmRevisionCurrent)
	n.ServerSealingKey = sealKey(n.NegotiateFlags, n.exportedSessionKey, "Server", ntlmRevisionCurrent)
	return
}

func ntlmV1Mac(message []byte, sequenceNumber uint32, handle *rc4P.Cipher, sealingKey, signingKey []byte, NegotiateFlags uint32) []byte {
	if NTLMSSP_NEGOTIATE_DATAGRAM.IsSet(NegotiateFlags) && NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.IsSet(NegotiateFlags) {
		handle, _ = reinitSealingKey(sealingKey, sequenceNumber)
	} else if NTLMSSP_NEGOTIATE_DATAGRAM.IsSet(NegotiateFlags) {
		// CONOR: Reinitializing the rc4 cipher on every requst, but not using the
		// algorithm as described in the MS-NTLM document. Just reinitialize it directly.
		handle, _ = rc4Init(sealingKey)
	}
	sig := mac(NegotiateFlags, handle, signingKey, sequenceNumber, message)
	return sig.Bytes()
}

/**************
 Server Session
**************/

type V1ServerSession struct {
	V1Session
}

func (n *V1ServerSession) GetSessionData() *SessionData {
	return &n.SessionData
}

func (n *V1ServerSession) SetServerChallenge(challenge []byte) {
	n.serverChallenge = challenge
}

func (n *V1ServerSession) SetTargetInfo(domainJoined bool, nbMachineName, nbDomainName, dnsMachineName, dnsDomainName, dnsForestName string) {
	n.domainJoined = domainJoined
	n.nbMachineName = nbMachineName
	n.nbDomainName = nbDomainName
	n.dnsMachineName = dnsMachineName
	n.dnsDomainName = dnsDomainName
	n.dnsForestName = dnsForestName
}

func (n *V1ServerSession) ProcessNegotiateMessage(nm *NegotiateMessage) (err error) {
	n.negotiateMessage = nm

	// Process the flags requested by client and accept what we can support/are our preferences
	flags, err := n.AcceptNegotiateFlags(nm.NegotiateFlags)
	if err != nil {
		return err
	}

	// Confirm that the client authentication policy has been met
	if err = n.CheckNegotiateFlags(flags); err != nil {
		return err
	}

	n.NegotiateFlags = flags
	return
}

func (n *V1ServerSession) GenerateChallengeMessage() (cm *ChallengeMessage, err error) {
	cm = new(ChallengeMessage)
	cm.Signature = []byte("NTLMSSP\x00")
	cm.MessageType = uint32(2)

	var flags uint32
	if NTLMSSP_NEGOTIATE_DATAGRAM.IsSet(n.configFlags) {
		// Connectionless mode - set initial config flags
		flags = n.InitialNegotiateFlags()

	} else {
		// Connection oriented mode - use flags from client
		flags = n.NegotiateFlags
	}

	flags = NTLMSSP_REQUEST_TARGET.Set(flags)
	flags = NTLMSSP_NEGOTIATE_TARGET_INFO.Set(flags)

	if NTLMSSP_REQUEST_TARGET.IsSet(flags) {
		if n.domainJoined {
			cm.TargetName, _ = CreateStringPayload(n.nbDomainName)
			flags = NTLMSSP_TARGET_TYPE_DOMAIN.Set(flags)
		} else {
			cm.TargetName, _ = CreateStringPayload(n.nbMachineName)
			flags = NTLMSSP_TARGET_TYPE_SERVER.Set(flags)
		}
	}

	cm.NegotiateFlags = flags

	n.serverChallenge = randomBytes(8)
	cm.ServerChallenge = n.serverChallenge
	cm.Reserved = make([]byte, 8)

	if NTLMSSP_NEGOTIATE_TARGET_INFO.IsSet(flags) {
		// Create the AvPairs we need
		pairs := new(AvPairs)
		if len(n.nbMachineName) > 0 {
			pairs.AddAvPair(MsvAvNbComputerName, utf16FromString(n.nbMachineName))
		}
		if len(n.nbDomainName) > 0 {
			pairs.AddAvPair(MsvAvNbDomainName, utf16FromString(n.nbDomainName))
		}
		if len(n.dnsMachineName) > 0 {
			pairs.AddAvPair(MsvAvDnsComputerName, utf16FromString(n.dnsMachineName))
		}
		if len(n.dnsDomainName) > 0 {
			pairs.AddAvPair(MsvAvDnsDomainName, utf16FromString(n.dnsDomainName))
		}
		if len(n.dnsForestName) > 0 {
			pairs.AddAvPair(MsvAvDnsTreeName, utf16FromString(n.dnsForestName))
		}

		cm.TargetInfo = pairs
		cm.TargetInfoPayloadStruct, _ = CreateBytePayload(pairs.Bytes())
	}

	if NTLMSSP_NEGOTIATE_VERSION.IsSet(cm.NegotiateFlags) {
		cm.Version = n.windowsVersion
	}

	// Connectionless mode - save negotiate flags to session
	if NTLMSSP_NEGOTIATE_DATAGRAM.IsSet(n.configFlags) {
		n.NegotiateFlags = cm.NegotiateFlags
	}

	n.challengeMessage = cm
	return cm, nil
}

func (n *V1ServerSession) ProcessAuthenticateMessage(am *AuthenticateMessage) (err error) {
	n.authenticateMessage = am

	// Confirm that the client authentication policy has been met
	if err = n.CheckNegotiateFlags(am.NegotiateFlags); err != nil {
		return err
	}

	n.NegotiateFlags = am.NegotiateFlags
	n.clientChallenge = am.ClientChallenge()
	n.encryptedRandomSessionKey = am.EncryptedRandomSessionKey.Payload

	// Ignore the values used in SetUserInfo and use these instead from the authenticate message
	// They should always be correct (I hope)
	n.user = am.UserName.String()
	n.userDomain = am.DomainName.String()
	log.Printf("(ProcessAuthenticateMessage)NTLM v1 User '%s' Domain '%s'", n.user, n.userDomain)

	err = n.fetchResponseKeys()
	if err != nil {
		return err
	}

	err = n.computeExpectedResponses()
	if err != nil {
		return err
	}

	if !bytes.Equal(am.NtChallengeResponseFields.Payload, n.ntChallengeResponse) {
		// There is a bug with the steps in MS-NLMP. In section 3.2.5.1.2 it says you should fall through
		// to compare the lmChallengeResponse if the ntChallengeRepsonse fails, but with extended session security
		// this would *always* pass because the lmChallengeResponse and expectedLmChallengeRepsonse will always
		// be the same
		if !bytes.Equal(am.LmChallengeResponse.Payload, n.lmChallengeResponse) || NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.IsSet(n.NegotiateFlags) {
			return errors.New("Could not authenticate")
		}
	}

	err = n.computeKeyExchangeKey()
	if err != nil {
		return err
	}

	n.mic = am.Mic
	am.Mic = zeroBytes(16)

	err = n.computeExportedSessionKey()
	if err != nil {
		return err
	}

	// If the server doesn't indicate their NTLM revision, assume zero
	ntlmRevision := uint8(0)
	if am.Version != nil {
		ntlmRevision = am.Version.NTLMRevisionCurrent
	}

	err = n.calculateKeys(ntlmRevision)
	if err != nil {
		return err
	}

	if am.NtlmV2Response != nil {
		if avFlags := am.NtlmV2Response.NtlmV2ClientChallenge.AvPairs.Find(MsvAvFlags); avFlags != nil && (avFlags.Value[3]&0x02 == 0x02) {
			// HMAC_MD5(ExportedSessionKey, ConcatenationOf( NEGOTIATE_MESSAGE, CHALLENGE_MESSAGE, AUTHENTICATE_MESSAGE))
			calculatedMic := hmacMd5(n.exportedSessionKey, concat(n.challengeMessage.Bytes(), am.Bytes()))
			if bytes.Compare(calculatedMic, n.mic) != 0 {
				err = fmt.Errorf("Authentication failure. MIC in authentication message does not match calculated MIC")
				return err
			}
		}
	}

	n.clientHandle, err = rc4Init(n.ClientSealingKey)
	if err != nil {
		return err
	}
	n.serverHandle, err = rc4Init(n.ServerSealingKey)
	if err != nil {
		return err
	}

	return nil
}

func (n *V1ServerSession) computeExportedSessionKey() (err error) {
	if NTLMSSP_NEGOTIATE_KEY_EXCH.IsSet(n.NegotiateFlags) && (NTLMSSP_NEGOTIATE_SIGN.IsSet(n.NegotiateFlags) || NTLMSSP_NEGOTIATE_SEAL.IsSet(n.NegotiateFlags)) {
		n.exportedSessionKey, err = rc4K(n.keyExchangeKey, n.encryptedRandomSessionKey)
		if err != nil {
			return err
		}
	} else {
		n.exportedSessionKey = n.keyExchangeKey
	}
	return nil
}

func (n *V1ServerSession) Mac(message []byte, sequenceNumber uint32) ([]byte, error) {
	mac := ntlmV1Mac(message, sequenceNumber, n.serverHandle, n.ServerSealingKey, n.ServerSigningKey, n.NegotiateFlags)
	return mac, nil
}

func (n *V1ServerSession) VerifyMac(message, expectedMac []byte, sequenceNumber uint32) (bool, error) {
	mac := ntlmV1Mac(message, sequenceNumber, n.clientHandle, n.ClientSealingKey, n.ClientSigningKey, n.NegotiateFlags)
	return MacsEqual(mac, expectedMac), nil
}

func (n *V1ServerSession) Wrap(message []byte, sequenceNumber uint32) (emessage, mac []byte, err error) {

	// Seal (if required)
	if NTLMSSP_NEGOTIATE_SEAL.IsSet(n.NegotiateFlags) {
		emessage = rc4(n.serverHandle, message)
	} else {
		copy(emessage, message)
	}

	// Sign
	mac, err = n.Mac(message, sequenceNumber)

	return emessage, mac, err
}

func (n *V1ServerSession) Unwrap(emessage []byte, expectedMac []byte, sequenceNumber uint32) (message []byte, ok bool, err error) {
	// Unseal (if required)
	if NTLMSSP_NEGOTIATE_SEAL.IsSet(n.NegotiateFlags) {
		message = rc4(n.clientHandle, emessage)
	} else {
		copy(message, emessage)
	}

	if ok, err := n.VerifyMac(message, expectedMac, sequenceNumber); err != nil {
		return nil, false, fmt.Errorf("Error unsealing message - %v", err)
	} else if !ok {
		return nil, false, fmt.Errorf("Error unsealing message - signature does not match")
	}

	return message, true, nil
}

/*************
 Client Session
**************/

type V1ClientSession struct {
	V1Session
}

func (n *V1ClientSession) SetMachineName(nbMachineName string) {
	n.nbMachineName = nbMachineName
}

func (n *V1ClientSession) GenerateNegotiateMessage() (nm *NegotiateMessage, err error) {
	nm = new(NegotiateMessage)
	nm.Signature = []byte("NTLMSSP\x00")
	nm.MessageType = uint32(1)

	nm.NegotiateFlags = n.InitialNegotiateFlags()

	if NTLMSSP_NEGOTIATE_VERSION.IsSet(nm.NegotiateFlags) {
		nm.WorkstationFields, _ = CreateStringPayload("")
		nm.DomainNameFields, _ = CreateStringPayload("")
		nm.Version = n.windowsVersion
	}

	// Save to represent the current set of negotiated flags
	n.NegotiateFlags = nm.NegotiateFlags

	return nm, nil
}

func (n *V1ClientSession) ProcessChallengeMessage(cm *ChallengeMessage) (err error) {
	n.challengeMessage = cm
	n.serverChallenge = cm.ServerChallenge

	// Produce the agreed set of flags for this session
	flags, err := n.AcceptNegotiateFlags(cm.NegotiateFlags)
	if err != nil {
		return err
	}

	// Confirm that the client authentication policy has been met
	if err = n.CheckNegotiateFlags(flags); err != nil {
		return err
	}

	n.NegotiateFlags = flags

	// Initialisation of these independent variables done here to provide an opportunity to override in test cases. See TestNTLMv2ClientAuthentication for example
	n.clientChallenge = randomBytes(8)
	n.exportedSessionKey = randomBytes(16)

	return nil
}

func (n *V1ClientSession) GenerateAuthenticateMessage() (am *AuthenticateMessage, err error) {
	am = new(AuthenticateMessage)
	am.Signature = []byte("NTLMSSP\x00")
	am.MessageType = uint32(3)
	cm := n.challengeMessage

	var avPairs = new(AvPairs)

	// Add Flag to indicate MAC will be calculated
	if cm.TargetInfoPayloadStruct != nil {
		avPairs = ReadAvPairs(cm.TargetInfoPayloadStruct.Payload)
		if avPairs.Find(MsvAvTimestamp) != nil {
			avFlags := avPairs.Find(MsvAvFlags)
			if avFlags != nil {
				avFlags.Value[3] = avFlags.Value[3] | 0x02
			} else {
				avPairs.AddAvPair(MsvAvFlags, []byte{0x00, 0x00, 0x00, 0x02})
			}
		}
	}

	err = n.fetchResponseKeys()
	if err != nil {
		return nil, err
	}

	err = n.computeExpectedResponses()
	if err != nil {
		return nil, err
	}

	err = n.computeKeyExchangeKey()
	if err != nil {
		return nil, err
	}

	err = n.computeEncryptedSessionKey()
	if err != nil {
		return nil, err
	}

	// If the server doesn't indicate their NTLM revision, assume zero
	ntlmRevision := uint8(0)
	if cm.Version != nil {
		ntlmRevision = cm.Version.NTLMRevisionCurrent
	}

	err = n.calculateKeys(ntlmRevision)
	if err != nil {
		return nil, err
	}

	n.clientHandle, err = rc4Init(n.ClientSealingKey)
	if err != nil {
		return nil, err
	}
	n.serverHandle, err = rc4Init(n.ServerSealingKey)
	if err != nil {
		return nil, err
	}

	am.LmChallengeResponse, _ = CreateBytePayload(n.lmChallengeResponse)
	am.NtChallengeResponseFields, _ = CreateBytePayload(n.ntChallengeResponse)
	am.DomainName, _ = CreateStringPayload(n.userDomain)
	am.UserName, _ = CreateStringPayload(n.user)

	// Set machine name to the server name returned in challenge message if windows version information is to be sent
	if NTLMSSP_NEGOTIATE_VERSION.IsSet(n.NegotiateFlags) {
		am.Version = n.windowsVersion
		am.Workstation, _ = CreateStringPayload(n.nbMachineName)
	}

	am.EncryptedRandomSessionKey, _ = CreateBytePayload(n.encryptedRandomSessionKey)
	am.NegotiateFlags = n.NegotiateFlags

	// Set MIC to HMAC_MD5(ExportedSessionKey, ConcatenationOf( CHALLENGE_MESSAGE, AUTHENTICATE_MESSAGE))late MAC
	if n.challengeMessage.TargetInfo != nil {
		if avTimestamp := n.challengeMessage.TargetInfo.Find(MsvAvTimestamp); avTimestamp != nil {
			am.Mic = hmacMd5(n.exportedSessionKey, concat(n.challengeMessage.Bytes(), am.Bytes()))
		}
	}

	return am, nil
}

func (n *V1ClientSession) computeEncryptedSessionKey() (err error) {
	if NTLMSSP_NEGOTIATE_KEY_EXCH.IsSet(n.NegotiateFlags) {
		n.encryptedRandomSessionKey, err = rc4K(n.keyExchangeKey, n.exportedSessionKey)
		if err != nil {
			return err
		}
	} else {
		n.exportedSessionKey = n.keyExchangeKey
		n.encryptedRandomSessionKey = n.keyExchangeKey
	}
	return nil
}

func (n *V1ClientSession) Mac(message []byte, sequenceNumber uint32) ([]byte, error) {
	mac := ntlmV1Mac(message, sequenceNumber, n.clientHandle, n.ClientSealingKey, n.ClientSigningKey, n.NegotiateFlags)
	return mac, nil
}

func (n *V1ClientSession) VerifyMac(message, expectedMac []byte, sequenceNumber uint32) (bool, error) {
	mac := ntlmV1Mac(message, sequenceNumber, n.serverHandle, n.ServerSealingKey, n.ServerSigningKey, n.NegotiateFlags)
	return MacsEqual(mac, expectedMac), nil
}

func (n *V1ClientSession) Wrap(message []byte, sequenceNumber uint32) (emessage, mac []byte, err error) {

	// Seal (if required)
	if NTLMSSP_NEGOTIATE_SEAL.IsSet(n.NegotiateFlags) {
		emessage = rc4(n.clientHandle, message)
	} else {
		copy(emessage, message)
	}

	// Sign
	mac, err = n.Mac(message, sequenceNumber)

	return emessage, mac, err
}

func (n *V1ClientSession) Unwrap(emessage []byte, expectedMac []byte, sequenceNumber uint32) (message []byte, ok bool, err error) {
	// Unseal (if required)
	if NTLMSSP_NEGOTIATE_SEAL.IsSet(n.NegotiateFlags) {
		message = rc4(n.serverHandle, emessage)
	} else {
		copy(message, emessage)
	}

	if ok, err := n.VerifyMac(message, expectedMac, sequenceNumber); err != nil {
		return nil, false, fmt.Errorf("Error unsealing message - %v", err)
	} else if !ok {
		return nil, false, fmt.Errorf("Error unsealing message - signature does not match")
	}

	return message, true, nil
}

/********************************
 NTLM V1 Password hash functions
*********************************/

func ntowfv1(passwd string) []byte {
	return md4(utf16FromString(passwd))
}

//	ConcatenationOf( DES( UpperCase( Passwd)[0..6],"KGS!@#$%"), DES( UpperCase( Passwd)[7..13],"KGS!@#$%"))
func lmowfv1(passwd string) ([]byte, error) {
	asciiPassword := []byte(strings.ToUpper(passwd))
	keyBytes := zeroPaddedBytes(asciiPassword, 0, 14)

	first, err := des(keyBytes[0:7], []byte("KGS!@#$%"))
	if err != nil {
		return nil, err
	}
	second, err := des(keyBytes[7:14], []byte("KGS!@#$%"))
	if err != nil {
		return nil, err
	}

	return append(first, second...), nil
}
