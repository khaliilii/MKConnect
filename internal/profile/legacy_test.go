package profile

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

// legacyEncrypt mirrors the v1 encryptPassword so the migration can be tested.
func legacyEncrypt(t *testing.T, password string) string {
	block, err := aes.NewCipher(legacyKey)
	if err != nil {
		t.Fatal(err)
	}
	pad := aes.BlockSize - len(password)%aes.BlockSize
	plain := []byte(password)
	for range pad {
		plain = append(plain, byte(pad))
	}
	out := make([]byte, aes.BlockSize+len(plain))
	cipher.NewCBCEncrypter(block, out[:aes.BlockSize]).CryptBlocks(out[aes.BlockSize:], plain)
	return base64.StdEncoding.EncodeToString(out)
}

func TestImportLegacy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := `{"userssh":"root","ssh_password_encrypted":"` + legacyEncrypt(t, "s3cret") + `","ip":"1.2.3.4","sshport":"22","socksport":"1090"}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	p, socks, err := ImportLegacy(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Password != "s3cret" || p.User != "root" || p.Port != 22 || socks != 1090 {
		t.Fatalf("unexpected result %+v socks=%d", p, socks)
	}
}

func TestLegacyDecryptRejectsGarbage(t *testing.T) {
	for _, in := range []string{"", base64.StdEncoding.EncodeToString(make([]byte, 16)), base64.StdEncoding.EncodeToString(make([]byte, 20))} {
		if _, err := legacyDecrypt(in); err == nil {
			t.Fatalf("expected error for %q", in)
		}
	}
}
