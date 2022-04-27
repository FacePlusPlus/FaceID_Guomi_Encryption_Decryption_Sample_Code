# FaceID国密(SM2)加解密python Demo
## 目录

[TOC]

## 依赖库

依赖pyasn1解析asn1
使用`pip install pyasn1 --upgrade --ignore-installed pyasn1` 进行安装

## 参考示例

算法参考 https://github.com/duanhongyi/gmssl

## 支持版本

支持PEM格式的公私钥，私钥目前支持EC PRIVATE KEY 和 PKCS8格式的PRIVATE KEY

## 代码说明

### 目录说明



```tree
├── asn1sm2.py                   # SM2算法
├── main.py                      # FaceID参数加解密和测试示例
├── image.jpg                    # 测试文件
├── README.md                    # 说明文档
```



### 测试Demo使用方法

`python3 main.py`