package tuya

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
)

// PKCS7Padding pads the data to block size
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// BuildProtocol22Frame applies Tuya's byte-validated message-2.2 framing:
// pv || CRC32(s || o || ciphertext) || s || o || ciphertext. Integer fields are
// big-endian and the CRC covers every byte after the CRC field.
func BuildProtocol22Frame(pv string, s, o uint32, ciphertext []byte) []byte {
	body := make([]byte, 8+len(ciphertext))
	binary.BigEndian.PutUint32(body[0:4], s)
	binary.BigEndian.PutUint32(body[4:8], o)
	copy(body[8:], ciphertext)

	frame := make([]byte, len(pv)+4+len(body))
	copy(frame, pv)
	binary.BigEndian.PutUint32(frame[len(pv):len(pv)+4], crc32.ChecksumIEEE(body))
	copy(frame[len(pv)+4:], body)
	return frame
}

// PKCS7Unpadding removes the padding
func PKCS7Unpadding(origData []byte) ([]byte, error) {
	length := len(origData)
	if length == 0 {
		return nil, fmt.Errorf("empty data")
	}
	unpadding := int(origData[length-1])
	if length < unpadding {
		return nil, fmt.Errorf("invalid padding")
	}
	return origData[:(length - unpadding)], nil
}

// AesEncryptECB encrypts data using AES in ECB mode
func AesEncryptECB(origData []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = PKCS7Padding(origData, blockSize)

	encrypted := make([]byte, len(origData))
	for bs, be := 0, blockSize; bs < len(origData); bs, be = bs+blockSize, be+blockSize {
		block.Encrypt(encrypted[bs:be], origData[bs:be])
	}
	return encrypted, nil
}

// AesDecryptECB decrypts data using AES in ECB mode
func AesDecryptECB(encrypted []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()

	if len(encrypted)%blockSize != 0 {
		return nil, fmt.Errorf("crypto/cipher: input not full blocks")
	}

	decrypted := make([]byte, len(encrypted))
	for bs, be := 0, blockSize; bs < len(encrypted); bs, be = bs+blockSize, be+blockSize {
		block.Decrypt(decrypted[bs:be], encrypted[bs:be])
	}

	return PKCS7Unpadding(decrypted)
}
