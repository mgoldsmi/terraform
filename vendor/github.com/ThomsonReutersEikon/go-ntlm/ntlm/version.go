//Copyright 2013 Thomson Reuters Global Resources. BSD License please see License file for more information

package ntlm

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type VersionStruct struct {
	ProductMajorVersion uint8
	ProductMinorVersion uint8
	ProductBuild        uint16
	Reserved            []byte
	NTLMRevisionCurrent uint8
}

const NTLMSSP_REVISION_W2K3 = 0x0F
const NTLMSSP_CURRENT_REVISION = NTLMSSP_REVISION_W2K3

func ReadVersionStruct(structSource []byte) (*VersionStruct, error) {
	versionStruct := new(VersionStruct)

	versionStruct.ProductMajorVersion = uint8(structSource[0])
	versionStruct.ProductMinorVersion = uint8(structSource[1])
	versionStruct.ProductBuild = binary.LittleEndian.Uint16(structSource[2:4])
	versionStruct.Reserved = structSource[4:7]
	versionStruct.NTLMRevisionCurrent = uint8(structSource[7])

	return versionStruct, nil
}

func (v *VersionStruct) String() string {
	return fmt.Sprintf("%d.%d.%d Ntlm %d", v.ProductMajorVersion, v.ProductMinorVersion, v.ProductBuild, v.NTLMRevisionCurrent)
}

func (v *VersionStruct) Bytes() []byte {
	dest := make([]byte, 0, 8)
	buffer := bytes.NewBuffer(dest)

	binary.Write(buffer, binary.LittleEndian, v.ProductMajorVersion)
	binary.Write(buffer, binary.LittleEndian, v.ProductMinorVersion)
	binary.Write(buffer, binary.LittleEndian, v.ProductBuild)
	buffer.Write(make([]byte, 3))
	binary.Write(buffer, binary.LittleEndian, uint8(v.NTLMRevisionCurrent))

	return buffer.Bytes()
}

var osVersions = map[string]VersionStruct{
	"Windows XP":                    VersionStruct{ProductMajorVersion: uint8(5), ProductMinorVersion: uint8(1), ProductBuild: uint16(2600)},
	"Windows XP SP1":                VersionStruct{ProductMajorVersion: uint8(5), ProductMinorVersion: uint8(1), ProductBuild: uint16(2600)},
	"Windows XP SP2":                VersionStruct{ProductMajorVersion: uint8(5), ProductMinorVersion: uint8(1), ProductBuild: uint16(2600)},
	"Windows XP SP3":                VersionStruct{ProductMajorVersion: uint8(5), ProductMinorVersion: uint8(1), ProductBuild: uint16(2600)},
	"Windows Server 2003":           VersionStruct{ProductMajorVersion: uint8(5), ProductMinorVersion: uint8(2), ProductBuild: uint16(3790)},
	"Windows Server 2003 SP1":       VersionStruct{ProductMajorVersion: uint8(5), ProductMinorVersion: uint8(2), ProductBuild: uint16(3790)},
	"Windows Vista":                 VersionStruct{ProductMajorVersion: uint8(6), ProductMinorVersion: uint8(0), ProductBuild: uint16(6000)},
	"Windows Vista SP2":             VersionStruct{ProductMajorVersion: uint8(6), ProductMinorVersion: uint8(0), ProductBuild: uint16(6002)},
	"Windows Home Server":           VersionStruct{ProductMajorVersion: uint8(5), ProductMinorVersion: uint8(2), ProductBuild: uint16(3790)},
	"Windows Server 2008":           VersionStruct{ProductMajorVersion: uint8(6), ProductMinorVersion: uint8(0), ProductBuild: uint16(6001)},
	"Windows Server 2008 R2":        VersionStruct{ProductMajorVersion: uint8(6), ProductMinorVersion: uint8(1), ProductBuild: uint16(7600)},
	"Windows Server 2008 R2 SP1":    VersionStruct{ProductMajorVersion: uint8(6), ProductMinorVersion: uint8(1), ProductBuild: uint16(7601)},
	"Windows 7":                     VersionStruct{ProductMajorVersion: uint8(6), ProductMinorVersion: uint8(1), ProductBuild: uint16(7600)},
	"Windows 7 SP1":                 VersionStruct{ProductMajorVersion: uint8(6), ProductMinorVersion: uint8(1), ProductBuild: uint16(7601)},
	"Windows 8":                     VersionStruct{ProductMajorVersion: uint8(6), ProductMinorVersion: uint8(2), ProductBuild: uint16(9200)},
	"Windows 8.1":                   VersionStruct{ProductMajorVersion: uint8(6), ProductMinorVersion: uint8(3), ProductBuild: uint16(9200)},
	"Windows 8.1 SP1":               VersionStruct{ProductMajorVersion: uint8(6), ProductMinorVersion: uint8(3), ProductBuild: uint16(9600)},
	"Windows 10":                    VersionStruct{ProductMajorVersion: uint8(10), ProductMinorVersion: uint8(0), ProductBuild: uint16(10240)},
	"Windows Home Server 2011":      VersionStruct{ProductMajorVersion: uint8(6), ProductMinorVersion: uint8(1), ProductBuild: uint16(8400)},
	"Windows Server 2012":           VersionStruct{ProductMajorVersion: uint8(6), ProductMinorVersion: uint8(2), ProductBuild: uint16(9200)},
	"Windows Server 2012 R2":        VersionStruct{ProductMajorVersion: uint8(6), ProductMinorVersion: uint8(3), ProductBuild: uint16(9200)},
	"Windows Server 2012 R2 Update": VersionStruct{ProductMajorVersion: uint8(6), ProductMinorVersion: uint8(3), ProductBuild: uint16(9600)},
	"Windows Server 2016":           VersionStruct{ProductMajorVersion: uint8(10), ProductMinorVersion: uint8(0), ProductBuild: uint16(14393)},
}

func GetVersion(name string) (VersionStruct, error) {
	vs, ok := osVersions[name]
	if !ok {
		err := fmt.Errorf("Unknown Windows OS version: %s", name)
		return vs, err
	}

	// Set the current NTLMSSP revision
	vs.NTLMRevisionCurrent = NTLMSSP_CURRENT_REVISION
	return vs, nil
}
