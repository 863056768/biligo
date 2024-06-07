package util

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
)

func Hmac(message, key string, hashFunc func() hash.Hash) string {
	h := hmac.New(hashFunc, []byte(key))
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

func HmacMD5(message, key string) string {
	return Hmac(message, key, md5.New)
}
func HmacSHA1(message, key string) string {
	return Hmac(message, key, sha1.New)
}
func HmacSHA256(message, key string) string {
	return Hmac(message, key, sha256.New)
}
func HmacSHA224(message, key string) string {
	return Hmac(message, key, sha256.New224)
}
func HmacSHA512(message, key string) string {
	return Hmac(message, key, sha512.New)
}
func HmacSHA384(message, key string) string {
	return Hmac(message, key, sha512.New384)
}
