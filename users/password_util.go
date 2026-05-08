package users

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"net/url"
)

// ====================== 配置（对应Java的SecretConst） ======================
const (
	privateKeyPem = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAMFSKTlf3BooSG6csZAEqM6LCz5IQnd3bSbOb07192kY13hjXTs+1N5IUd3YeLVJf7sIiqQOvukGi/mqVJbuIV5SEdM7nrDL2jdz57Sd09DjRXvxHrXG8iVr7r44IA01bMAEJUY/Wa878fAybOswvelMeuqGSvKvRM7SnDm91BD/AgMBAAECgYADnc/bnOl3K82/E/tWYF/wDTXWom9r4LYQBcibR4qrUqWlQOablx9QUTYG2mfXrFpRW2WMkCIOJes0bnVKpYXGP5vJzcq/sxUMw/YO/JYPVb8oDJsd546pOQOeVzS1OXn1gNyGC2RheQyoh4mN34YVNTc89TRiDMXKMZMWaEV1AQJBAOGiWGyMbzF+UxrJiLF6Gq2m5gXtrK/a29qoBPpCRSIGYuT7G5jZm42IaX3rL4Ln73mOjHPdzYu9p0ZhPGTMdL8CQQDbVouZ6xs3pQHJs+YL3vLN8pHKypzJS76RhKpz8BEe2JYqBGRMn6KgL5Cv5T/WxYk2pBVQXxoKFjIe9uvxEjPBAkAj+I3AQGM5sLnu+1IfeSfnp0Pkjg+JuYpzQXYJr6b11a7Ocnnj1E1IMwceW/AnHnK/Hkql7iZmsMWKItZN+4phAkAfHJeQrZieu/kU8z+eT3GBZPbpHPRAWU4etgK3j0Xeajpim1zewYX/0r9jM9FqVXqxFXUwgUzgQWW6nqu49iwBAkAJ52zBMyMWdojlH16eWSWF61/UCa1h2ucCmd9rFrz3UkQfMCbyOJP87zr/UEg+/pQVxC3vgzOfJa6naXAPHRJK"
)

// ====================== 重写PasswordUtil核心函数 ======================

func decryptByPrivate(encryptedStr, privateKeyStr string) (string, error) {
	// 1. 解码私钥的 Base64
	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyStr)
	if err != nil {
		return "", fmt.Errorf("failed to decode private key: %v", err)
	}

	// 2. 解析 PKCS#8 格式的私钥
	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %v", err)
	}

	// 转换为 *rsa.PrivateKey
	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("private key is not RSA")
	}

	// 3. 解码加密数据的 Base64
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedStr)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted data: %v", err)
	}

	// 4. 使用 RSA 解密（PKCS#1 v1.5 填充，默认）
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, rsaPrivateKey, ciphertext)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %v", err)
	}

	// 5. 返回 UTF-8 字符串
	return string(plaintext), nil
}

func bCryptEncode(passwordBeforeEncryption string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(passwordBeforeEncryption), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return "{bcrypt}" + string(hash), nil
}

func BCryptEncode(passwordBeforeEncryption string) (string, error) {
	return bCryptEncode(passwordBeforeEncryption)
}

func GetPlaintext(password string) (string, error) {
	// 假设你有一个解密函数，这里用一个简单的示例
	encrypted, err := url.QueryUnescape(password)
	if err != nil {
		return "", err
	}
	decryptedPassword, err := decryptByPrivate(encrypted, privateKeyPem)
	if err != nil {
		return "", err
	}
	return decryptedPassword, nil
}
