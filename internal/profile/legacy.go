package profile

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

// legacyKey is the fixed key MKConnect <= v1 used to "encrypt" config.json.
// It is only kept so old configs can be migrated.
var legacyKey = []byte("12345678901234567890123456789012")

type legacyConfig struct {
	UserSSH    string `json:"userssh"`
	SSHPassEnc string `json:"ssh_password_encrypted"`
	IP         string `json:"ip"`
	SSHPort    string `json:"sshport"`
	SocksPort  string `json:"socksport"`
}

// ImportLegacy reads a v1 config.json and returns the SSH profile and SOCKS port it described.
func ImportLegacy(path string) (Profile, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, 0, err
	}
	var c legacyConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return Profile{}, 0, fmt.Errorf("parse %s: %w", path, err)
	}
	pass, err := legacyDecrypt(c.SSHPassEnc)
	if err != nil {
		return Profile{}, 0, fmt.Errorf("decrypt password: %w", err)
	}
	port, err := strconv.Atoi(c.SSHPort)
	if err != nil {
		return Profile{}, 0, fmt.Errorf("bad ssh port %q", c.SSHPort)
	}
	socksPort, _ := strconv.Atoi(c.SocksPort)
	p := Profile{Name: "ssh-" + c.IP, Type: TypeSSH, Server: c.IP, Port: port, User: c.UserSSH, Password: pass}
	return p, socksPort, p.Validate()
}

func legacyDecrypt(encrypted string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	if len(data) < 2*aes.BlockSize || len(data)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext has invalid length")
	}
	block, err := aes.NewCipher(legacyKey)
	if err != nil {
		return "", err
	}
	iv, body := data[:aes.BlockSize], data[aes.BlockSize:]
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(body, body)
	pad := int(body[len(body)-1])
	if pad == 0 || pad > aes.BlockSize {
		return "", fmt.Errorf("invalid padding")
	}
	for _, b := range body[len(body)-pad:] {
		if int(b) != pad {
			return "", fmt.Errorf("invalid padding")
		}
	}
	return string(body[:len(body)-pad]), nil
}
