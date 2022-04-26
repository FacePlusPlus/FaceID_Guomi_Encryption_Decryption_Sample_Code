import base64
import asn1sm2
import struct
import os


# SM2示例代码

# 参数SM2加密示例代码
class Sm2Crypt():
    def __init__(self):
        self.asn1sm2 = asn1sm2.CryptSM2()

    def generatekey(self):
        return self.asn1sm2.generatekey()

    def initKey(self, private_key, public_key):
        self.asn1sm2.initKey(private_key=private_key, public_key=public_key)

    def encryptText(self, message):
        encode_info = self.asn1sm2.encrypt(message.encode(encoding="utf-8"))
        return str(base64.encodebytes(encode_info), encoding="utf-8")

    def decryptText(self, message):
        decode_info = self.asn1sm2.decrypt(base64.decodebytes(message.encode(encoding="utf-8")))
        return decode_info

    def encryptFile(self, src_file_path):
        if os.path.exists(src_file_path) == False:
            return None

        fsize = os.path.getsize(src_file_path)
        encode_len = fsize
        if fsize > 1024:
            encode_len = 1024

        f = open(src_file_path, "rb")
        data = f.read()
        f.close()

        encode = self.asn1sm2.encrypt(data[:encode_len])

        plain = data[encode_len:]
        end = struct.pack('<L', len(encode))
        return str(base64.encodebytes(encode + plain + end), encoding="utf-8")

    def decryptFile(self, fileStr, out_path):
        if fileStr is None or len(fileStr) == 0:
            return

        data = base64.decodebytes(fileStr.encode(encoding="utf-8"))
        encode_len = struct.unpack('<L', data[-4:])[0]

        decode = self.asn1sm2.decrypt(data[:encode_len])

        f = open(out_path, "wb")
        f.write(decode)
        f.write(data[encode_len:-4])
        f.close()


if __name__ == "__main__":
    print("############## test  start ################### ")

    print("############## test  genkey ################### ")
    sm2 = Sm2Crypt()
    private_key, public_key = sm2.generatekey()

    print("private_key : ", private_key)
    print("public_key : ", public_key)



    sm2.initKey(private_key, public_key)

    print("############## test  text ################### ")
    text = "this is src message ..."
    encode = sm2.encryptText(text)
    print("encode : ", encode)

    decode = sm2.decryptText(encode)
    print("decode : ", decode)

    print("############## test  file ################### ")

    data = sm2.encryptFile(src_file_path="image.jpg")
    f = open("encode.jpg", "wb")
    f.write(data.encode(encoding="utf-8"))
    f.close()

    print("encode data : ", data)

    f = open("encode.jpg", "rb")
    data = str(f.read(), encoding="utf-8")
    f.close()

    sm2.decryptFile(fileStr=data, out_path="dec_file.jpg")

    print("############## test  end ################### ")
