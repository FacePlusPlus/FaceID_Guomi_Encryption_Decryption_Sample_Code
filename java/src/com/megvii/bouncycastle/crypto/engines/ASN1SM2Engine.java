package com.megvii.bouncycastle.crypto.engines;


import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

/**
 * 修复 org.bouncycastle.crypto.engines.SM2Engine类中，加解密没有支持ASN1序列化的BUG。
 * 根据之前某个版本的SM2标准，C1是P点的坐标，C2是加密密文，C3是HASH值，并未强调ASN1序列化。
 * 因国密标准不严谨的问题，原jar包没有对记过进行ASN1编码，但 openssl，C，python，golang等多种语音的库，均需要对结果做ASN1.
 * 为了统一标准，该类的加密增加了对结果的ASN1.
 */
public class ASN1SM2Engine {
    private final Digest digest;
    private final ASN1SM2Engine.Mode mode;
    private boolean forEncryption;
    private ECKeyParameters ecKey;
    private ECDomainParameters ecParams;
    private int curveLength;
    private SecureRandom random;
    private boolean isDebug = false;

    /**
     * 构造函数，同org.bouncycastle.crypto.engines.SM2Engine
     */
    public ASN1SM2Engine() {
        this((Digest) (new SM3Digest()));
    }

    /**
     * 构造函数，同org.bouncycastle.crypto.engines.SM2Engine
     * @param var1
     */
    public ASN1SM2Engine(ASN1SM2Engine.Mode var1) {
        this(new SM3Digest(), var1);
    }

    /**
     * 构造函数，同org.bouncycastle.crypto.engines.SM2Engine
     * @param var1
     */
    public ASN1SM2Engine(Digest var1) {
        this(var1, ASN1SM2Engine.Mode.C1C2C3);
    }

    /**
     * 构造函数，同org.bouncycastle.crypto.engines.SM2Engine
     * @param var1
     * @param var2
     */
    public ASN1SM2Engine(Digest var1, ASN1SM2Engine.Mode var2) {
        if (var2 == null) {
            throw new IllegalArgumentException("mode cannot be NULL");
        } else {
            this.digest = var1;
            this.mode = var2;
        }
    }

    /**
     * 是否输出调试日志
     * @param flag
     */
    public void setDebug(boolean flag) {
        isDebug = flag;
    }

    /**
     * 初始化接口，同org.bouncycastle.crypto.engines.SM2Engine.init
     * @param var1
     * @param var2
     */
    public void init(boolean var1, CipherParameters var2) {
        this.forEncryption = var1;
        if (var1) {
            ParametersWithRandom var3 = (ParametersWithRandom) var2;
            this.ecKey = (ECKeyParameters) var3.getParameters();
            this.ecParams = this.ecKey.getParameters();
            ECPoint var4 = ((ECPublicKeyParameters) this.ecKey).getQ().multiply(this.ecParams.getH());
            if (var4.isInfinity()) {
                throw new IllegalArgumentException("invalid key: [h]Q at infinity");
            }

            this.random = var3.getRandom();
        } else {
            this.ecKey = (ECKeyParameters) var2;
            this.ecParams = this.ecKey.getParameters();
        }

        this.curveLength = (this.ecParams.getCurve().getFieldSize() + 7) / 8;
    }

    /**
     * 区块加解密，同org.bouncycastle.crypto.engines.SM2Engine.processBlock
     * @param var1
     * @param var2
     * @param var3
     * @return
     * @throws InvalidCipherTextException
     */
    public byte[] processBlock(byte[] var1, int var2, int var3) throws InvalidCipherTextException {
        return this.forEncryption ? this.encrypt(var1, var2, var3) : this.decrypt(var1, var2, var3);
    }

    /**
     * 获取输出长度，同org.bouncycastle.crypto.engines.SM2Engine.getOutputSize
     * @param var1
     * @return
     */
    public int getOutputSize(int var1) {
        return 1 + 2 * this.curveLength + var1 + this.digest.getDigestSize();
    }

    /**
     * 创建basePoint，同同org.bouncycastle.crypto.engines.SM2Engine.createBasePointMultiplier
     * @return
     */
    protected ECMultiplier createBasePointMultiplier() {
        return new FixedPointCombMultiplier();
    }

    /**
     * 加密函数，增加对结果的ASN1编码
     * @param var1
     * @param var2
     * @param var3
     * @return
     * @throws InvalidCipherTextException
     */
    private byte[] encrypt(byte[] var1, int var2, int var3) throws InvalidCipherTextException {
        if (isDebug) {
            System.out.println("encrypt start .....");
            System.out.println("mode : " + this.mode);
            System.out.print("input : " + var1.length + "  [");
            for (byte b : var1) {
                System.out.print((b & 0xFF) >= 0x0F ? Integer.toHexString(b & 0xFF) : "0" + Integer.toHexString(b & 0xFF));
            }
            System.out.println("] ");
        }

        byte[] var4 = new byte[var3];
        System.arraycopy(var1, var2, var4, 0, var4.length);

        ECMultiplier var5 = this.createBasePointMultiplier();
        ECPoint C1;
        ECPoint var7;
        do {
            BigInteger var8 = this.nextK();
            C1 = var5.multiply(this.ecParams.getG(), var8).normalize();
            var7 = ((ECPublicKeyParameters) this.ecKey).getQ().multiply(var8).normalize();
            this.kdf(this.digest, var7, var4);
        } while (this.notEncrypted(var4, var1, var2));

        byte[] var10 = new byte[this.digest.getDigestSize()];
        this.addFieldElement(this.digest, var7.getAffineXCoord());
        this.digest.update(var1, var2, var3);
        this.addFieldElement(this.digest, var7.getAffineYCoord());
        this.digest.doFinal(var10, 0);

        ASN1EncodableVector asn1EncodableVector = new ASN1EncodableVector();

        /**
         * 对结果进行编码
         */
        ASN1Integer x = new ASN1Integer(C1.getXCoord().toBigInteger());
        ASN1Integer y = new ASN1Integer(C1.getYCoord().toBigInteger());

        DEROctetString C2 = new DEROctetString(var4);
        DEROctetString C3 = new DEROctetString(var10);

        switch (this.mode) {
            case C1C3C2:
                asn1EncodableVector.add(x);
                asn1EncodableVector.add(y);
                asn1EncodableVector.add(C3);
                asn1EncodableVector.add(C2);
                break;
            default:
                asn1EncodableVector.add(x);
                asn1EncodableVector.add(y);
                asn1EncodableVector.add(C2);
                asn1EncodableVector.add(C3);
                break;
        }

        DERSequence seq = new DERSequence(asn1EncodableVector);
        byte[] ret = null;
        try {
            ret = seq.getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
        }

        /**
         * 调试日志
         */
        if (isDebug) {
            System.out.print("C1 : " + C1.getEncoded(false).length + "  [");
            for (byte b : C1.getEncoded(false)) {
                System.out.print((b & 0xFF) >= 0x0F ? Integer.toHexString(b & 0xFF) : "0" + Integer.toHexString(b & 0xFF));
            }
            System.out.println("] ");

            System.out.print("C2 : " + var4.length + "  [");
            for (byte b : var4) {
                System.out.print((b & 0xFF) >= 0x0F ? Integer.toHexString(b & 0xFF) : "0" + Integer.toHexString(b & 0xFF));
            }
            System.out.println("] ");

            System.out.print("C3 : " + var10.length + "  [");
            for (byte b : var10) {
                System.out.print((b & 0xFF) >= 0x0F ? Integer.toHexString(b & 0xFF) : "0" + Integer.toHexString(b & 0xFF));
            }
            System.out.println("] ");
            System.out.println("encrypt end .....");
        }

        return ret;
    }

    /**
     * 解密接口，增加ASN1解码
     * @param var1
     * @param var2
     * @param var3
     * @return
     * @throws InvalidCipherTextException
     */
    private byte[] decrypt(byte[] var1, int var2, int var3) throws InvalidCipherTextException {
        /**
         * 调试日志
         */
        if (isDebug) {
            System.out.println("decrypt start .....");
            System.out.println("mode : " + this.mode);
            System.out.print("input : " + var1.length + "  [");
            for (byte b : var1) {
                System.out.print((b & 0xFF) >= 0x0F ? Integer.toHexString(b & 0xFF) : "0" + Integer.toHexString(b & 0xFF));
            }
            System.out.println("] ");
        }

        try {
            /**
             * 对结果进行解码
             */
            ASN1InputStream aIn = new ASN1InputStream(var1);
            ASN1Sequence seq = (ASN1Sequence) aIn.readObject();
            aIn.close();

            BigInteger x = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
            BigInteger y = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();
            byte[] C3 = ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets();
            byte[] C2 = ASN1OctetString.getInstance(seq.getObjectAt(3)).getOctets();

            ECPoint p = this.ecParams.getCurve().validatePoint(x, y);
            byte[] C1 = p.getEncoded(false);


            if (this.mode == Mode.C1C3C2) {
                var1 = Arrays.concatenate(C1, C3, C2);
                var3 = var1.length;
            } else {
                var1 = Arrays.concatenate(C1, C2, C3);
                var3 = var1.length;
            }

            if (isDebug) {

                System.out.print("C1 : " + C1.length + "  [");
                for (byte b : C1) {
                    System.out.print((b & 0xFF) >= 0x0F ? Integer.toHexString(b & 0xFF) : "0" + Integer.toHexString(b & 0xFF));
                }
                System.out.println("] ");

                System.out.print("C2 : " + C2.length + "  [");
                for (byte b : C2) {
                    System.out.print((b & 0xFF) >= 0x0F ? Integer.toHexString(b & 0xFF) : "0" + Integer.toHexString(b & 0xFF));
                }
                System.out.println("] ");

                System.out.print("C3 : " + C3.length + "  [");
                for (byte b : C3) {
                    System.out.print((b & 0xFF) >= 0x0F ? Integer.toHexString(b & 0xFF) : "0" + Integer.toHexString(b & 0xFF));
                }
                System.out.println("] ");

                System.out.print("encryptData : " + var1.length + "  [");
                for (byte b : var1) {
                    System.out.print((b & 0xFF) >= 0x0F ? Integer.toHexString(b & 0xFF) : "0" + Integer.toHexString(b & 0xFF));
                }
                System.out.println("] ");
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new InvalidCipherTextException("invalid cipher ASN1 error text");
        }

        byte[] var4 = new byte[this.curveLength * 2 + 1];
        System.arraycopy(var1, var2, var4, 0, var4.length);
        ECPoint var5 = this.ecParams.getCurve().decodePoint(var4);
        ECPoint var6 = var5.multiply(this.ecParams.getH());
        if (var6.isInfinity()) {
            throw new InvalidCipherTextException("[h]C1 at infinity");
        } else {
            var5 = var5.multiply(((ECPrivateKeyParameters) this.ecKey).getD()).normalize();
            int var7 = this.digest.getDigestSize();
            byte[] var8 = new byte[var3 - var4.length - var7];
            if (this.mode == ASN1SM2Engine.Mode.C1C3C2) {
                System.arraycopy(var1, var2 + var4.length + var7, var8, 0, var8.length);
            } else {
                System.arraycopy(var1, var2 + var4.length, var8, 0, var8.length);
            }

            this.kdf(this.digest, var5, var8);
            byte[] var9 = new byte[this.digest.getDigestSize()];
            this.addFieldElement(this.digest, var5.getAffineXCoord());
            this.digest.update(var8, 0, var8.length);
            this.addFieldElement(this.digest, var5.getAffineYCoord());
            this.digest.doFinal(var9, 0);
            int var10 = 0;
            int var11;
            if (this.mode == ASN1SM2Engine.Mode.C1C3C2) {
                for (var11 = 0; var11 != var9.length; ++var11) {
                    var10 |= var9[var11] ^ var1[var2 + var4.length + var11];
                }
            } else {
                for (var11 = 0; var11 != var9.length; ++var11) {
                    var10 |= var9[var11] ^ var1[var2 + var4.length + var8.length + var11];
                }
            }

            Arrays.fill(var4, (byte) 0);
            Arrays.fill(var9, (byte) 0);
            if (var10 != 0) {
                Arrays.fill(var8, (byte) 0);
                throw new InvalidCipherTextException("invalid cipher text");
            } else {
                if (isDebug) {
                    System.out.println("decrypt end .....");
                }
                return var8;
            }
        }
    }

    /**
     * 同org.bouncycastle.crypto.engines.SM2Engine.notEncrypted
     * @param var1
     * @param var2
     * @param var3
     * @return
     */
    private boolean notEncrypted(byte[] var1, byte[] var2, int var3) {
        for (int var4 = 0; var4 != var1.length; ++var4) {
            if (var1[var4] != var2[var3 + var4]) {
                return false;
            }
        }

        return true;
    }

    /**
     * 计算KDF,同org.bouncycastle.crypto.engines.SM2Engine.kdf
     * @param var1
     * @param var2
     * @param var3
     */
    private void kdf(Digest var1, ECPoint var2, byte[] var3) {
        int var4 = var1.getDigestSize();
        byte[] var5 = new byte[Math.max(4, var4)];
        int var6 = 0;
        Memoable var7 = null;
        Memoable var8 = null;
        if (var1 instanceof Memoable) {
            this.addFieldElement(var1, var2.getAffineXCoord());
            this.addFieldElement(var1, var2.getAffineYCoord());
            var7 = (Memoable) var1;
            var8 = var7.copy();
        }

        int var10;
        for (int var9 = 0; var6 < var3.length; var6 += var10) {
            if (var7 != null) {
                var7.reset(var8);
            } else {
                this.addFieldElement(var1, var2.getAffineXCoord());
                this.addFieldElement(var1, var2.getAffineYCoord());
            }

            ++var9;
            Pack.intToBigEndian(var9, var5, 0);
            var1.update(var5, 0, 4);
            var1.doFinal(var5, 0);
            var10 = Math.min(var4, var3.length - var6);
            this.xor(var3, var5, var6, var10);
        }

    }

    /**
     * 计算XOR，同org.bouncycastle.crypto.engines.SM2Engine.xor
     * @param var1
     * @param var2
     * @param var3
     * @param var4
     */
    private void xor(byte[] var1, byte[] var2, int var3, int var4) {
        for (int var5 = 0; var5 != var4; ++var5) {
            var1[var3 + var5] ^= var2[var5];
        }

    }

    /**
     * 同org.bouncycastle.crypto.engines.SM2Engine.nextK
     * @return
     */
    private BigInteger nextK() {
        int var1 = this.ecParams.getN().bitLength();

        BigInteger var2;
        do {
            do {
                var2 = BigIntegers.createRandomBigInteger(var1, this.random);
            } while (var2.equals(BigIntegers.ZERO));
        } while (var2.compareTo(this.ecParams.getN()) >= 0);

        return var2;
    }

    /**
     * 同org.bouncycastle.crypto.engines.SM2Engine.addFieldElement
     * @param var1
     * @param var2
     */
    private void addFieldElement(Digest var1, ECFieldElement var2) {
        byte[] var3 = BigIntegers.asUnsignedByteArray(this.curveLength, var2.toBigInteger());
        var1.update(var3, 0, var3.length);
    }

    public static enum Mode {
        C1C2C3,
        C1C3C2;

        private Mode() {
        }
    }
}
