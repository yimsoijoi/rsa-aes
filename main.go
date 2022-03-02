package main

// PowerShell new Env
// New-Item -Path Env:\ -Name FOO -Value "BAR"
// PowerShell update Env
// $env:FOO = "BAR"

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
)

type rsaKeyPair struct {
	pub *rsa.PublicKey
	pri *rsa.PrivateKey
}

func rsaParseKeys(pub, pri string) *rsaKeyPair {
	block, _ := pem.Decode([]byte(pub))
	pubInf, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatalln("failed to get publicKey interface")
	}
	var ok bool
	pubKey, ok := pubInf.(*rsa.PublicKey)
	if !ok {
		log.Fatal("failed to asset type *rsa.PublicKey")
	}

	block, _ = pem.Decode([]byte(pri))
	priKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal("failed to parse privateKey")
	}
	return &rsaKeyPair{
		pub: pubKey,
		pri: priKey,
	}
}

func main() {
	pubEnv := os.Getenv("PUB_KEY")
	priEnv := os.Getenv("PRI_KEY")

	var pubKeyString string
	var priKeyString string
	if len(pubEnv) > 0 {
		pubKeyString = pubEnv
		priKeyString = priEnv
	} else {
		pubKeyString = defaultRsaPubkey
		priKeyString = defaultRsaPriKey
	}

	rsaKeyPair := rsaParseKeys(pubKeyString, priKeyString)

	rsaCiphertext := encryptRsa("01234567890123456789012345678901", rsaKeyPair.pub)
	rsaPlaintext := decryptRsa(rsaCiphertext, rsaKeyPair.pri)
	keyFromRsa := rsaPlaintext

	var aesKey string
	if len(keyFromRsa) != 32 {
		aesKey = defaultAesKey
		fmt.Println("aeskey changed to default")
	} else {
		aesKey = keyFromRsa
	}
	aesCiphertext := encryptAES([]byte("success combine encryption!"), aesKey)
	aesPlaintext := decryptAES(aesCiphertext, aesKey)
	fmt.Println(string(aesPlaintext))

}

func encryptRsa(plaintext string, key *rsa.PublicKey) string {
	hash := sha256.New()
	salt := rand.Reader
	ciphertext, err := rsa.EncryptOAEP(hash, salt, key, []byte(plaintext), nil)
	if err != nil {
		log.Fatal("failed to encryptRsa")
	}
	return string(ciphertext)
}

func decryptRsa(ciphertext string, key *rsa.PrivateKey) string {
	hash := sha256.New()
	salt := rand.Reader
	plaintext, err := rsa.DecryptOAEP(hash, salt, key, []byte(ciphertext), nil)
	if err != nil {
		log.Fatal("failed to decrypt")
	}
	return string(plaintext)
}

func encryptAES(data []byte, key string) []byte {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatal("failed to create block")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal("failed to wrap gcm")
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatal("can't read nonce")
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func decryptAES(ciphertext []byte, key string) []byte {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Fatal("failed to create block")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal("failed to wrap gcm")
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		log.Fatal("can't sizing nonce")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Fatal("can't open gcm")
	}
	return plaintext
}

var (
	defaultRsaPubkey = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAscetx8F1Q7H67ZSgIcTw
zQfCf919iACii2o5sh+1l7N62nE9zBpSx3OEgNv64l8v4OchXMU8gKk28piExpdQ
kvzDW5VK7STmEuIZ7IqWKsZge1YmGDsyIFw74V9Uslhc05t7VKYhWWFPAKfouPPM
3ZKe5ZiALAjvLVIEUYYnQ452H2RJGuGYJeKvPiNtOwKSLA/ROwvE/1I+0S+gq1hd
+GbrYPJLfj77pkZJKnf/ye3rgbQglfBQzSHSDKuwC6xNZEWMR4DBzraE0MeKrNhN
4PFxKpkyVRPftrahbiTA6ohvoBsSyD+RdT1dRde4qbJGXuW6AQ2DQYNPWqTdVDNo
kwIDAQAB
-----END PUBLIC KEY-----
`
	defaultRsaPriKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAscetx8F1Q7H67ZSgIcTwzQfCf919iACii2o5sh+1l7N62nE9
zBpSx3OEgNv64l8v4OchXMU8gKk28piExpdQkvzDW5VK7STmEuIZ7IqWKsZge1Ym
GDsyIFw74V9Uslhc05t7VKYhWWFPAKfouPPM3ZKe5ZiALAjvLVIEUYYnQ452H2RJ
GuGYJeKvPiNtOwKSLA/ROwvE/1I+0S+gq1hd+GbrYPJLfj77pkZJKnf/ye3rgbQg
lfBQzSHSDKuwC6xNZEWMR4DBzraE0MeKrNhN4PFxKpkyVRPftrahbiTA6ohvoBsS
yD+RdT1dRde4qbJGXuW6AQ2DQYNPWqTdVDNokwIDAQABAoIBACnS6iVGdAn7AyeF
ga6wIF575twiBXhLffICiZRINXZ8+PgPEBTGVJcrrA6MshczgZYNiiHDHRq/tHea
PhJiYshRwrv3AWuM9LuYibTGXdGuXeBmQgwNURuf106MGObkNuJpf7hIZSwb4nQr
DGsGoDm4Vr15BR5W873bv7xWLUKNCpPwo65pGJHTCTjBm6AC0doQ/WbN+V9ly2B6
uz2Afl9wrQlTZUUHLFuvO9IjukCCj0ZclPocsURA0j3TF47kXmZxhYT5wCerzZRO
tgfJXd0sGvoBZTS5OpEVG3ef/EFbyDLy76QwsItaphJlgCCyXwFOTDxDQQWd6uPA
3V9/lWECgYEA6p74OccfFythzHZN/SOk4bC5bUKWw6umE0h0t3lQN7bCtddDu2RH
xR4SFlIA8fL6Vp4BkseydRg3mMHz+UZ5E5EaRPWWQHU0Spn9qnrO0QTuWeQJlpN0
6f0Am2pZeh6voRbbzAC3yKGI5frdDLtM2p2k/gbGlWTB5e0L2UGAUNkCgYEAwfrF
7UWIrCqx2abgsGNfHp4omwhfv8jpD4CGpXKGrHvnagGfLYABngbmIo0GLHyUR0Rm
wE2qfeDp+64vvNj+RV4lRME1PNFsWxaJ8eMUHr06lDO51Cy1lhTWymT4NXj+Esys
dFJvCElfwxbZjflyNf8hfkSa24Rfo6WoI9jV4UsCgYEA4HJZlrRVms2mjnmym/LI
Xhu5F7v3DJMdmh7bgVWtls7gsCKRqigBvKHKvc2PF+bQ86HOcYNWxkv3i8wnwJVZ
aI2MauHh7iHxd1ifYcKALVchSZ8sSP8hfmLJfOQdWwUWEO4UMLGTH3zgwNnfM7nO
iOj8mQMUYIB2OaYuipTt0ukCgYEAl4qRHAdJea81GCNtv38ybVoDwPIu00ZjBNBU
4GXzXkbCCCfSMhqhqNIc8fsYSqLcuDxwxWUnf4W5ZfyzoKYpJwogtXD3ZVb6fsLB
662KJ2WPoP4z+9Ud22zWTHHLEwM+AnPRemJ4CZJA9MkiFu88UYDKqrlv/XSRvugI
zlB07rcCgYEAueo9hE02p0iSqxXWru8zu7PxY8Gy2+tksMZb4PWB5C732BMr3ryP
lz5UUW+5iBe/z54HOdmBbVdd3G+fRlkCm9XUex0GlwaN3g45k8rcyJi/8iRexIpF
2c3olpk+wO+d7ciK+7Qc8uHYyZlnBxQu6FIRDTE/Y8QOkU97/BDSkYQ=
-----END RSA PRIVATE KEY-----
`
	defaultAesKey = "passphrasewhichneedstobe32bytes!"
)
