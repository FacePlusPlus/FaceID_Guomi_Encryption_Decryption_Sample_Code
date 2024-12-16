package com.megvii.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;

import java.io.File;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import cn.hutool.crypto.ECKeyUtil;
import cn.hutool.crypto.SecureUtil;

public class TestCryptTextAndFile {


    /**
     * 加密文本示例
     * @param textMessage
     * @param publicKey
     * @return
     */
    public String encryptText(String textMessage, ECPublicKeyParameters publicKey) {
        ASN1SM2Engine sm2Engine = new ASN1SM2Engine(ASN1SM2Engine.Mode.C1C3C2);
        sm2Engine.init(true, (CipherParameters) (new ParametersWithRandom(publicKey)));

        String resStr = "";
        try {
            byte[] encrypt = sm2Engine.processBlock(textMessage.getBytes(), 0, textMessage.getBytes().length);
            resStr = Base64.toBase64String(encrypt);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return resStr;
    }

    /**
     * 解密文本示例
     * @param textMessage
     * @param privateKey
     * @return
     */
    public String decryptText(String textMessage, ECPrivateKeyParameters privateKey) {
        ASN1SM2Engine sm2Engine = new ASN1SM2Engine(ASN1SM2Engine.Mode.C1C3C2);
        sm2Engine.init(false, (CipherParameters) (privateKey));

        String resStr = "";
        try {
            byte[] input = Base64.decode(textMessage);
            byte[] decrypt = sm2Engine.processBlock(input, 0, input.length);
            resStr = new String(decrypt);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return resStr;
    }


    /**
     * 加密文件示例
     * @param file
     * @param publicKey
     * @return
     */
    public String encodeFile(File file, ECPublicKeyParameters publicKey) {
        if (file == null || !file.exists() || file.isDirectory()) {
            return null;
        }

        ASN1SM2Engine sm2Engine = new ASN1SM2Engine(ASN1SM2Engine.Mode.C1C3C2);
        sm2Engine.init(true, (CipherParameters) (new ParametersWithRandom(publicKey)));

        long fileLen = file.length();
        int len = 1024;

        if (fileLen < 1024) {
            len = (int) fileLen;
        }
        String resStr = "";

        byte[] buff = new byte[len];
        byte[] plain = new byte[(int) fileLen - len];

        try {
            RandomAccessFile fileDataSource = new RandomAccessFile(file, "r");
            fileDataSource.seek(0);
            fileDataSource.read(buff);

            byte[] encrypt = sm2Engine.processBlock(buff, 0, len);
            fileDataSource.seek(len);

            fileDataSource.read(plain);

            fileDataSource.close();
            ByteBuffer byteBuffer = ByteBuffer.allocate(4);
            byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
            byteBuffer.putInt(encrypt.length);


            resStr = Base64.toBase64String(Arrays.concatenate(encrypt, plain, byteBuffer.array()));
        } catch (Exception e) {
            e.printStackTrace();
        }

        return resStr;
    }

    /**
     * 解密文件示例
     * @param fileStr
     * @param resFile
     * @param privateKey
     * @return
     */
    public boolean decodeFile(String fileStr, File resFile, ECPrivateKeyParameters privateKey) {
        boolean flag = false;

        ASN1SM2Engine sm2Engine = new ASN1SM2Engine(ASN1SM2Engine.Mode.C1C3C2);
        sm2Engine.init(false, (CipherParameters) (privateKey));

        byte[] input = Base64.decode(fileStr);

        ByteBuffer byteBuffer = ByteBuffer.wrap(input, input.length - 4, 4);
        byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
        int len = byteBuffer.getInt();

        try {
            byte[] decrypt = sm2Engine.processBlock(input, 0, len);
            FileOutputStream fos = new FileOutputStream(resFile);
            fos.write(decrypt);
            fos.write(input, len, input.length - len - 4);
            fos.close();
            flag = true;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return flag;
    }

//    -----BEGIN EC PRIVATE KEY-----
//    MHcCAQEEIC7nVWFIyN3dq/3ohywjD3QQw8lAmT5zHXT38ArLPvAToAoGCCqBHM9V
//    AYItoUQDQgAERyca3tDWv+yN5cyE5fA3MuJTGJnVTnvugvpEFQ8ZHpXW3ykkZOct
//    SkfD9Q7lhIXtJp5zFGwYkObu52FYOPzysw==
//            -----END EC PRIVATE KEY-----
//
//  -----BEGIN PUBLIC KEY-----
//    MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAERyca3tDWv+yN5cyE5fA3MuJTGJnV
//    TnvugvpEFQ8ZHpXW3ykkZOctSkfD9Q7lhIXtJp5zFGwYkObu52FYOPzysw==
//            -----END PUBLIC KEY-----

    /**
     * 调用Demo:
     * @param args
     */
    public static void main(String[] args) {

        String privateKeyStr =
////            "-----BEGIN EC PRIVATE KEY-----\n" +
                "MHcCAQEEIF4rmRMcTQFkAGWqD1lIrePavx/mSHZbuIY3TA54dFwSoAoGCCqBHM9V\n" +
                        "AYItoUQDQgAESbX+j49UfdZl0HrY9JxUvF6aPfprkLImNTgUYqDSHOUR3uFihGZK\n" +
                        "K7Mtvc8jfdsyCQlukpDBF0IqUq8gWl1MZA==\n";
////            "-----END EC PRIVATE KEY-----\n";
//
        String publicKeyStr =
////            "-----BEGIN PUBLIC KEY-----\n" +
                "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAESbX+j49UfdZl0HrY9JxUvF6aPfpr\n" +
                        "kLImNTgUYqDSHOUR3uFihGZKK7Mtvc8jfdsyCQlukpDBF0IqUq8gWl1MZA==\n";
////            "-----END PUBLIC KEY-----\n";

        long startTime = System.currentTimeMillis();
        ECPrivateKeyParameters privateKey = ECKeyUtil.decodePrivateKeyParams(SecureUtil.decode(privateKeyStr));
        System.out.println("decodePrivateKeyParams key 耗时：" + (System.currentTimeMillis() - startTime) + " ms");

        startTime = System.currentTimeMillis();
        ECPublicKeyParameters publicKey = ECKeyUtil.decodePublicKeyParams(SecureUtil.decode(publicKeyStr));
        System.out.println("decodePublicKeyParams key 耗时：" + (System.currentTimeMillis() - startTime) + " ms");
        System.out.println(publicKey.getQ());
        System.out.print("publicKey.getQ().getEncoded(false) : " + publicKey.getQ().getEncoded(false).length + " [");
        for (byte b : publicKey.getQ().getEncoded(false)) {
            System.out.print((b & 0xff) > 0x0f ? Integer.toHexString(b & 0xff) : "0" + Integer.toHexString(b & 0xff));
            System.out.print("");
        }
        System.out.print("]\n");


        String name = "张晓明";
        TestCryptTextAndFile example = new TestCryptTextAndFile();

        startTime = System.currentTimeMillis();
        String encodeName = example.encryptText(name, publicKey);
        System.out.println("encryptText 耗时：" + (System.currentTimeMillis() - startTime) + " ms");
        System.out.println(encodeName);

        startTime = System.currentTimeMillis();
        String decName = example.decryptText(encodeName, privateKey);
        System.out.println("decryptText 耗时：" + (System.currentTimeMillis() - startTime) + " ms");
        System.out.println(decName);

        String id = "110011196708020012";

        startTime = System.currentTimeMillis();
        String encodeID = example.encryptText(id, publicKey);
        System.out.println("encryptText ID 耗时：" + (System.currentTimeMillis() - startTime) + " ms");
        System.out.println(encodeID);

        startTime = System.currentTimeMillis();
        String decID = example.decryptText(encodeID, privateKey);
        System.out.println("decryptText ID 耗时：" + (System.currentTimeMillis() - startTime) + " ms");
        System.out.println(decID);

        File file = new File("demo_beauty.jpg");
        startTime = System.currentTimeMillis();
        String fileStr = example.encodeFile(file, publicKey);
        System.out.println("encodeFile 耗时：" + (System.currentTimeMillis() - startTime) + " ms");
        System.out.println(fileStr);

        File decFile = new File("demo_beauty1.jpg");
        startTime = System.currentTimeMillis();
        example.decodeFile(fileStr, decFile, privateKey);
        System.out.println("decodeFile 耗时：" + (System.currentTimeMillis() - startTime) + " ms");

    }
}
