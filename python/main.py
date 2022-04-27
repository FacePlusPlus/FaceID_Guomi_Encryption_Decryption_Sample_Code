import base64
import asn1sm2
import struct
import os


# SM2示例代码

# 参数SM2加密示例代码
class Sm2Crypt():
    def __init__(self):
        self.asn1sm2 = asn1sm2.CryptSM2()

    # 生成公私钥
    def generatekey(self):
        return self.asn1sm2.generatekey()

    # 设置公私钥，加密必须有公钥，解密必须有私钥
    def initKey(self, private_key, public_key):
        self.asn1sm2.initKey(private_key=private_key, public_key=public_key)

    # 加密文字
    def encryptText(self, message):
        encode_info = self.asn1sm2.encrypt(message.encode(encoding="utf-8"))
        return str(base64.encodebytes(encode_info), encoding="utf-8")

    # 解密文字
    def decryptText(self, message):
        decode_info = self.asn1sm2.decrypt(base64.decodebytes(message.encode(encoding="utf-8")))
        return decode_info

    # 加密文件
    def encryptFile(self, src_file_path):
        if os.path.exists(src_file_path) == False:
            return None

        fsize = os.path.getsize(src_file_path)

        # 仅加密文件的前1024字节，如果文件小于1024，全文加密
        encode_len = fsize
        if fsize > 1024:
            encode_len = 1024

        f = open(src_file_path, "rb")
        data = f.read()
        f.close()

        encode = self.asn1sm2.encrypt(data[:encode_len])

        plain = data[encode_len:]

        # 记录加密后的文件长度，小端存储
        end = struct.pack('<L', len(encode))

        # 进行加密后数据base64拼接
        return str(base64.encodebytes(encode + plain + end), encoding="utf-8")

    # 解密文件
    def decryptFile(self, fileStr, out_path):
        if fileStr is None or len(fileStr) == 0:
            return

        data = base64.decodebytes(fileStr.encode(encoding="utf-8"))

        # 获取加密的文件长度，小端存储
        encode_len = struct.unpack('<L', data[-4:])[0]

        decode = self.asn1sm2.decrypt(data[:encode_len])

        f = open(out_path, "wb")
        f.write(decode)
        f.write(data[encode_len:-4])
        f.close()


if __name__ == "__main__":
    print("############## test  start ################### ")

    print("############## test  genkey ################### ")

    # 初始化对象
    sm2 = Sm2Crypt()

    # 生成公私钥
    private_key, public_key = sm2.generatekey()

    print("private_key : ", private_key)
    print("public_key : ", public_key)

    #设置密钥,加密必须需要设置公钥，解密必须设置私钥
    sm2.initKey(private_key, public_key)

    print("############## test  text ################### ")
    text = "this is src message ..."
    # 加密字符串
    encode = sm2.encryptText(text)
    print("encode : ", encode)

    # 解密字符串
    decode = sm2.decryptText(encode)
    print("decode : ", decode)

    print("############## test  file ################### ")

    # 加密文件
    data = sm2.encryptFile(src_file_path="image.jpg")

    # 将加密后的内容写入文件
    f = open("encode.jpg", "wb")
    f.write(data.encode(encoding="utf-8"))
    f.close()

    print("encode data : ", data)

    # 读取加密的文件内容
    f = open("encode.jpg", "rb")
    data = str(f.read(), encoding="utf-8")
    f.close()

    # 解密文件
    sm2.decryptFile(fileStr=data, out_path="dec_file.jpg")

    print("############## test  end ################### ")
