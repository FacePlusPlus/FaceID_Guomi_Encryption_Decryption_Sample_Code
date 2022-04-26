package main

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
)

var (
	// 两种模型, FaceIDV5中使用C1C2C3
	C1C3C2 = 0
	C1C2C3 = 1
	// 生成公钥和私钥保存地址
	PrivateKeyFile = "private_key.pem"
	PublicKeyFile  = "public_key.pem"
	// 测试图片
	TestImageName          = "superman.jpg"
	TestEncryptedImageName = "superman_encrypted"
	TestDecryptedImageName = "superman_decrypted.jpg"
)

// 从Pem文件中读取PublicKey和PrivateKey
func GetSM2KeyPair() (*sm2.PrivateKey, *sm2.PublicKey, error) {
	// Get private key from file
	privateKeyFile := PrivateKeyFile
	privateParser := NewPrivateParser()
	content, ioErr := privateParser.ReadFromFile(privateKeyFile)
	if ioErr != nil {
		log.Fatalf("read private key from file failed, err: %v\n", ioErr)
	}

	ret, parseErr := privateParser.Parse(content)
	if parseErr != nil {
		log.Fatalf("private parser parse failed, err: %v\n", parseErr)
	}
	privateKey := ret.(*sm2.PrivateKey)

	// Get public key from file
	publicParser := NewPublicParser()
	publicKeyFile := PublicKeyFile
	content, ioErr = publicParser.ReadFromFile(publicKeyFile)
	if ioErr != nil {
		log.Fatalf("read public key from file failed, err: %v\n", ioErr)
	}

	ret, parseErr = publicParser.Parse(content)
	if parseErr != nil {
		log.Fatalf("public parser parse failed, err: %v\n", parseErr)
	}
	publicKey := ret.(*sm2.PublicKey)

	return privateKey, publicKey, nil
}

func GenerateKeyPairs() {
	privateKey, sm2Err := sm2.GenerateKey(rand.Reader)
	if sm2Err != nil {
		log.Fatalf("generate private key failed, err: %v\n", sm2Err)
	}
	publicKey := &privateKey.PublicKey

	// no password, set pwd=nil
	privateKeyBytes, x509Err := x509.WritePrivateKeyToPem(privateKey, nil)
	if x509Err != nil {
		log.Println("write private key to pem failed, err: %v\n", x509Err)
		return
	}
	ioErr := ioutil.WriteFile(PrivateKeyFile, privateKeyBytes, 0644)
	if ioErr != nil {
		log.Fatalf("write private key to file failed, err: %v\n", ioErr)
	}

	publicKeyBytes, x509Err := x509.WritePublicKeyToPem(publicKey)
	if x509Err != nil {
		log.Fatalf("write public key to pem failed, err: %v\n", x509Err)
	}
	ioErr = ioutil.WriteFile(PublicKeyFile, publicKeyBytes, 0644)
	if ioErr != nil {
		log.Fatalf("write public key to file failed, err: %v\n", ioErr)
	}
}

func TestTextEncryptAndDecrypt() {
	// 读取公钥私钥
	privateKey, publicKey, err := GetSM2KeyPair()
	if err != nil {
		log.Fatalf("get sm2 key pairs failed, err: %v\n", err)
	}

	// 公钥加密
	text := []byte("Hello World")
	clipherText, err := publicKey.EncryptAsn1(text, rand.Reader)
	if err != nil {
		log.Fatalf("sm2 encrypt failed, err: %v\n", err)
	}
	clipherBase64Text := base64.StdEncoding.EncodeToString(clipherText)
	log.Printf("clipher base64 text = %s\n", clipherBase64Text)

	// 私钥解密
	clipherText, base64Err := base64.StdEncoding.DecodeString(clipherBase64Text)
	if base64Err != nil {
		log.Fatalf("base64 decode failed, err: %v\n", err)
	}
	clearText, err := privateKey.DecryptAsn1(clipherText)
	if err != nil {
		log.Fatalf("sm2 decrypt failed, err: %v\n", err)
	}
	log.Printf("clear text = %s\n", string(clearText))

	// 检查是否正确
	if strings.Compare(string(text), string(clearText)) != 0 {
		log.Fatalf("sm2 decrypt text failed, %s != %s", string(text), string(clearText))
	}
}

func TestImageEncrypt() {
	// 读取公钥私钥
	_, publicKey, err := GetSM2KeyPair()
	if err != nil {
		log.Fatalf("get sm2 key pairs failed, err: %v\n", err)
	}

	// 读取测试图片
	imageFileName := TestImageName
	rawImage, ioErr := ioutil.ReadFile(imageFileName)
	if ioErr != nil {
		log.Fatalf("read image file failed, err: %v\n", ioErr)
	}

	// 对图片加密
	encryptData, clearData := rawImage[:1024], rawImage[1024:]
	clipherImage, err := publicKey.EncryptAsn1(encryptData, rand.Reader)
	if err != nil {
		log.Fatalf("encrypt image failed, err: %v\n", clipherImage)
	}

	buffer := make([]byte, 4)
	binary.LittleEndian.PutUint32(buffer, uint32(len(clipherImage)))

	result := append(clipherImage, clearData...)
	result = append(result, buffer...)
	encryptedImage := base64.StdEncoding.EncodeToString(result)

	// 将加密结果保存到文件
	ioErr = ioutil.WriteFile(TestEncryptedImageName, []byte(encryptedImage), 0644)
	if ioErr != nil {
		log.Fatalf("write encrypted image to file failed, err: %v\n", ioErr)
	}
}

func TestImageDecrypt() {
	// 读取公钥私钥
	privateKey, _, err := GetSM2KeyPair()
	if err != nil {
		log.Fatalf("get sm2 key pairs failed, err: %v\n", err)
	}

	// 读取加密后的测试图片
	imageFileName := TestEncryptedImageName
	data, ioErr := ioutil.ReadFile(imageFileName)
	if ioErr != nil {
		log.Fatalf("read encrypted image file failed, err: %v\n", ioErr)
	}

	encryptedImage, base64Err := base64.StdEncoding.DecodeString(string(data))
	if base64Err != nil {
		log.Fatalf("base64 decode encrypted image failed, err: %v\n", base64Err)
	}

	// 对图片解密
	encryptedLength := binary.LittleEndian.Uint32(encryptedImage[len(encryptedImage)-4:])
	if uint32(len(encryptedImage)) < encryptedLength+4 {
		log.Fatalf("invalid encrypted image with incorrect encrypted length")
	}

	clipherImageBytes := encryptedImage[:encryptedLength]
	rawImageBytes, err := privateKey.DecryptAsn1(clipherImageBytes)
	if err != nil {
		log.Fatalf("decrypt image failed, err: %v\n", err)
	}

	clearImageBytes := encryptedImage[encryptedLength : len(encryptedImage)-4]
	originalImage := append(rawImageBytes, clearImageBytes...)

	// 将解密后的图片保存到另一文件, 用于比较
	ioErr = ioutil.WriteFile(TestDecryptedImageName, originalImage, 0644)
	if ioErr != nil {
		log.Fatalf("write decrypted image to file failed, err: %v\n", ioErr)
	}
}

func CheckImage() {
	// 读取测试图片
	imageFileName := TestImageName
	rawImage, ioErr := ioutil.ReadFile(imageFileName)
	if ioErr != nil {
		log.Fatalf("read image file failed, err: %v\n", ioErr)
	}

	imageFileName = TestDecryptedImageName
	decryptedImage, ioErr := ioutil.ReadFile(imageFileName)
	if ioErr != nil {
		log.Fatalf("read decrypted image file failed, err: %v\n", ioErr)
	}

	rawImageMD5 := fmt.Sprintf("%x", md5.Sum(rawImage))
	decryptedImageMD5 := fmt.Sprintf("%x", md5.Sum(decryptedImage))
	if strings.Compare(rawImageMD5, decryptedImageMD5) != 0 {
		log.Fatal("sm2 decrypt image failed")
	}
}

func main() {
	// 生成公钥/私钥文件
	GenerateKeyPairs()
	log.Println("generate key pairs finished")

	// 测试对文本的加解密
	TestTextEncryptAndDecrypt()
	log.Println("test text encrypt and decrypt finished")

	// 测试对图片的加密
	TestImageEncrypt()
	log.Println("test image encrypt finished")

	// 测试对图片的解密
	TestImageDecrypt()
	log.Println("test image decrypt finished")

	// 使用md5检查两文件是否一致
	CheckImage()
	log.Println("raw image and decrypted image md5 check finished")

	log.Println("done")
}
