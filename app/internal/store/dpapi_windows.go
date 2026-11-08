package store

import (
	"encoding/base64"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func takeBlob(out *windows.DataBlob) []byte {
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...)
}

// Encrypt шифрует строку ключом текущего пользователя Windows.
func Encrypt(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	var out windows.DataBlob
	if err := windows.CryptProtectData(blob([]byte(plain)), nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return "", fmt.Errorf("не удалось зашифровать секрет: %w", err)
	}
	return base64.StdEncoding.EncodeToString(takeBlob(&out)), nil
}

// Decrypt расшифровывает строку, полученную от Encrypt.
func Decrypt(enc string) (string, error) {
	if enc == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", fmt.Errorf("секрет повреждён: %w", err)
	}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(blob(raw), nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return "", fmt.Errorf("не удалось расшифровать секрет: %w", err)
	}
	return string(takeBlob(&out)), nil
}
