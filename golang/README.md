# sm2demo

FaceID国密(SM2)加解密Go Demo.


参考https://github.com/tjfoc/gmsm


**注意** 使用v1.4.0及以上版本, 之前版本缺少对加密解密ASN.1的支持。

## 目录说明
```
.
├── go.mod                      #
├── go.sum                      #
├── main.go                     # 入口
├── Makefile
├── parser.go                   # 读取公钥私
├── private_key.pem             # 生成私钥存储地址
├── public_key.pem              # 生成公钥存储地址
├── README.md
├── sm2demo                     # 编译生成的文件
├── superman_decrypted.jpg      # 测试图片-加解密之后的 
├── superman_encrypted          # 测试图片-加密之后的
└── superman.jpg                # 测试图片-原图
```


## 测试Demo使用方法

`make run`

