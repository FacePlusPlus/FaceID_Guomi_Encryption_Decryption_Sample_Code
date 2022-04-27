# FaceID国密(SM2)加解密java Demo

## 目录

[TOC]

## 依赖库

依赖jdk 1.8.0及以上版本的java环境。

依赖hutool工具包，本Demo中已经从远端下载到libs目录下。

## 代码说明

### 目录说明

```tree
├── src 												 # FaceID加解密源代码和测试代码
├── libs												 # 依赖的jar包 		
├── demo_beauty.jpg              # 测试所需要的图片
├── build.sh 										 # 编译Demo脚本
├── mainfest                     # 编译测试jar包配置
├── README.md                    # 说明文档
```



### 测试Demo使用方法

#### 编译测试demo

```shell
chmod 755 build.sh
./build.sh
```

#### 执行测试demo

```shell
java -jar test.jar 
```

