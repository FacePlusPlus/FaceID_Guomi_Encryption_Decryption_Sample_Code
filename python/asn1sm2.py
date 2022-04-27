import binascii
import re
import base64

from random import SystemRandom
from gmssl import sm3, func

from pyasn1.codec.der.encoder import encode
from pyasn1.codec.der.decoder import decode
from pyasn1.type.namedtype import *
from pyasn1.type.univ import *

PEM_STRING_PKCS8INF = "PRIVATE"
PEM_STRING_ECPRIVATEKEY = "ECPRIVATE"
PEM_STRING_PUBLICKEY = "PUBLIC"

# 选择素域，设置椭圆曲线参数

default_ecc_table = {
    'n': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
    'p': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',
    'g': '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7' \
         'bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0',
    'a': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',
    'b': '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',
}


class C1C3C2(Sequence):
    componentType = NamedTypes(
            NamedType("x", Integer()),
            NamedType("y", Integer()),
            NamedType("C3", OctetString()),
            NamedType("C2", OctetString())
    )


class PrivateKey(Sequence):
    componentType = NamedTypes(
            NamedType("field-0", Integer()),
            NamedType("field-1", OctetString()),
            NamedType("field-2", ObjectIdentifier()),
            NamedType("field-3", BitString())
    )


class PublicKey(Sequence):
    componentType = NamedTypes(
            NamedType("field-0", ObjectIdentifier()),
            NamedType("field-1", BitString())
    )


class CryptSM2(object):
    def __init__(self, ecc_table=default_ecc_table):
        self.para_len = len(ecc_table['n'])
        self.ecc_a3 = (
                          int(ecc_table['a'], base=16) + 3) % int(ecc_table['p'], base=16)
        self.ecc_table = ecc_table

    def _decode_key(self, pem_key):
        if pem_key is None or pem_key == "":
            return None

        try:
            r_start = re.compile(r"\s*-----BEGIN (.*)KEY-----\s+")
            r_end = re.compile(r"-----END (.*)KEY-----\s*$")

            m_start = r_start.search(pem_key)
            m_end = r_end.search(pem_key)

            tag_start = m_start.groups(1)[0].replace(" ", '')
            tag_end = m_end.groups(1)[0].replace(" ", '')

        except AttributeError:
            raise ValueError("key format error,check your keys : [", pem_key, "]")

        if not m_start or not m_end or tag_start != tag_end:
            raise ValueError("Not a valid PEM support !!!")

        start = m_start.end()
        end = m_end.start()

        lines = pem_key[start:end].replace(" ", '')

        key_map, _ = decode(base64.decodebytes(bytes(lines, encoding="utf-8")))

        if tag_start == PEM_STRING_ECPRIVATEKEY:
            return key_map["field-1"].prettyPrint()
        elif tag_start == PEM_STRING_PKCS8INF:
            key, _ = decode(key_map["field-2"])
            return key["field-1"].prettyPrint()
        elif tag_start == PEM_STRING_PUBLICKEY:
            return key_map["field-1"].asOctets()[1:].hex()
        else:
            return None

    def _kg(self, k, Point):  # kP运算
        Point = '%s%s' % (Point, '1')
        mask_str = '8'
        for i in range(self.para_len - 1):
            mask_str += '0'
        mask = int(mask_str, 16)
        Temp = Point
        flag = False
        for n in range(self.para_len * 4):
            if (flag):
                Temp = self._double_point(Temp)
            if (k & mask) != 0:
                if (flag):
                    Temp = self._add_point(Temp, Point)
                else:
                    flag = True
                    Temp = Point
            k = k << 1
        return self._convert_jacb_to_nor(Temp)

    def _double_point(self, Point):  # 倍点
        l = len(Point)
        len_2 = 2 * self.para_len
        if l < self.para_len * 2:
            return None
        else:
            x1 = int(Point[0:self.para_len], 16)
            y1 = int(Point[self.para_len:len_2], 16)
            if l == len_2:
                z1 = 1
            else:
                z1 = int(Point[len_2:], 16)

            T6 = (z1 * z1) % int(self.ecc_table['p'], base=16)
            T2 = (y1 * y1) % int(self.ecc_table['p'], base=16)
            T3 = (x1 + T6) % int(self.ecc_table['p'], base=16)
            T4 = (x1 - T6) % int(self.ecc_table['p'], base=16)
            T1 = (T3 * T4) % int(self.ecc_table['p'], base=16)
            T3 = (y1 * z1) % int(self.ecc_table['p'], base=16)
            T4 = (T2 * 8) % int(self.ecc_table['p'], base=16)
            T5 = (x1 * T4) % int(self.ecc_table['p'], base=16)
            T1 = (T1 * 3) % int(self.ecc_table['p'], base=16)
            T6 = (T6 * T6) % int(self.ecc_table['p'], base=16)
            T6 = (self.ecc_a3 * T6) % int(self.ecc_table['p'], base=16)
            T1 = (T1 + T6) % int(self.ecc_table['p'], base=16)
            z3 = (T3 + T3) % int(self.ecc_table['p'], base=16)
            T3 = (T1 * T1) % int(self.ecc_table['p'], base=16)
            T2 = (T2 * T4) % int(self.ecc_table['p'], base=16)
            x3 = (T3 - T5) % int(self.ecc_table['p'], base=16)

            if (T5 % 2) == 1:
                T4 = (T5 + ((T5 + int(self.ecc_table['p'], base=16)) >> 1) - T3) % int(self.ecc_table['p'], base=16)
            else:
                T4 = (T5 + (T5 >> 1) - T3) % int(self.ecc_table['p'], base=16)

            T1 = (T1 * T4) % int(self.ecc_table['p'], base=16)
            y3 = (T1 - T2) % int(self.ecc_table['p'], base=16)

            form = '%%0%dx' % self.para_len
            form = form * 3
            return form % (x3, y3, z3)

    def _add_point(self, P1, P2):  # 点加函数，P2点为仿射坐标即z=1，P1为Jacobian加重射影坐标
        len_2 = 2 * self.para_len
        l1 = len(P1)
        l2 = len(P2)
        if (l1 < len_2) or (l2 < len_2):
            return None
        else:
            X1 = int(P1[0:self.para_len], 16)
            Y1 = int(P1[self.para_len:len_2], 16)
            if (l1 == len_2):
                Z1 = 1
            else:
                Z1 = int(P1[len_2:], 16)
            x2 = int(P2[0:self.para_len], 16)
            y2 = int(P2[self.para_len:len_2], 16)

            T1 = (Z1 * Z1) % int(self.ecc_table['p'], base=16)
            T2 = (y2 * Z1) % int(self.ecc_table['p'], base=16)
            T3 = (x2 * T1) % int(self.ecc_table['p'], base=16)
            T1 = (T1 * T2) % int(self.ecc_table['p'], base=16)
            T2 = (T3 - X1) % int(self.ecc_table['p'], base=16)
            T3 = (T3 + X1) % int(self.ecc_table['p'], base=16)
            T4 = (T2 * T2) % int(self.ecc_table['p'], base=16)
            T1 = (T1 - Y1) % int(self.ecc_table['p'], base=16)
            Z3 = (Z1 * T2) % int(self.ecc_table['p'], base=16)
            T2 = (T2 * T4) % int(self.ecc_table['p'], base=16)
            T3 = (T3 * T4) % int(self.ecc_table['p'], base=16)
            T5 = (T1 * T1) % int(self.ecc_table['p'], base=16)
            T4 = (X1 * T4) % int(self.ecc_table['p'], base=16)
            X3 = (T5 - T3) % int(self.ecc_table['p'], base=16)
            T2 = (Y1 * T2) % int(self.ecc_table['p'], base=16)
            T3 = (T4 - X3) % int(self.ecc_table['p'], base=16)
            T1 = (T1 * T3) % int(self.ecc_table['p'], base=16)
            Y3 = (T1 - T2) % int(self.ecc_table['p'], base=16)

            form = '%%0%dx' % self.para_len
            form = form * 3
            return form % (X3, Y3, Z3)

    def _convert_jacb_to_nor(self, Point):  # Jacobian加重射影坐标转换成仿射坐标
        len_2 = 2 * self.para_len
        x = int(Point[0:self.para_len], 16)
        y = int(Point[self.para_len:len_2], 16)
        z = int(Point[len_2:], 16)
        z_inv = pow(z, int(self.ecc_table['p'], base=16) - 2, int(self.ecc_table['p'], base=16))
        z_invSquar = (z_inv * z_inv) % int(self.ecc_table['p'], base=16)
        z_invQube = (z_invSquar * z_inv) % int(self.ecc_table['p'], base=16)
        x_new = (x * z_invSquar) % int(self.ecc_table['p'], base=16)
        y_new = (y * z_invQube) % int(self.ecc_table['p'], base=16)
        z_new = (z * z_inv) % int(self.ecc_table['p'], base=16)
        if z_new == 1:
            form = '%%0%dx' % self.para_len
            form = form * 2
            return form % (x_new, y_new)
        else:
            return None

    def generatekey(self):
        k = SystemRandom().randrange(1, int(self.ecc_table['n'], base=16))
        print(k, type(k))
        print(len(hex(k)), hex(k), type(hex(k)))

        point = self._kg(k, self.ecc_table['g'])
        print("po : ", len(point))

        x = point[0:self.para_len]
        y = point[self.para_len:2 * self.para_len]

        xy = "00" + x + y

        print(x, type(x))

        privatekey = "-----BEGIN EC PRIVATE KEY-----\n"

        privatekey_data = PrivateKey()
        privatekey_data["field-0"] = Integer(1)
        privatekey_data["field-1"] = OctetString(hexValue="{:064X}".format(k))
        privatekey_data["field-2"] = ObjectIdentifier("1.2.156.10197.1.301")
        privatekey_data["field-3"] = BitString(hexValue=xy)

        privatekey += str(base64.encodebytes(encode(privatekey_data)), encoding="utf-8")
        privatekey += "-----END EC PRIVATE KEY-----"

        print("privatekey : ", privatekey)

        publickey = "-----BEGIN PUBLIC KEY-----\n"

        publickey_data = PublicKey()
        publickey_data["field-0"] = ObjectIdentifier("1.2.156.10197.1.301")
        publickey_data["field-1"] = BitString(hexValue=xy)

        publickey += str(base64.encodebytes(encode(publickey_data)), encoding="utf-8")
        publickey += "-----END PUBLIC KEY-----"

        print("len : ", len(xy))

        print("publickey : ", publickey)

        return privatekey, publickey

    def initKey(self, private_key, public_key):
        self.private_key = self._decode_key(private_key)
        self.public_key = self._decode_key(public_key)

    def verify(self, Sign, data):
        # 验签函数，sign签名r||s，E消息hash，public_key公钥
        r = int(Sign[0:self.para_len], 16)
        s = int(Sign[self.para_len:2 * self.para_len], 16)
        e = int(data.hex(), 16)
        t = (r + s) % int(self.ecc_table['n'], base=16)
        if t == 0:
            return 0

        P1 = self._kg(s, self.ecc_table['g'])
        P2 = self._kg(t, self.public_key)

        if P1 == P2:
            P1 = '%s%s' % (P1, 1)
            P1 = self._double_point(P1)
        else:
            P1 = '%s%s' % (P1, 1)
            P1 = self._add_point(P1, P2)
            P1 = self._convert_jacb_to_nor(P1)

        x = int(P1[0:self.para_len], 16)
        return (r == ((e + x) % int(self.ecc_table['n'], base=16)))

    def sign(self, data, K):  # 签名函数, data消息的hash，private_key私钥，K随机数，均为16进制字符串
        E = data.hex()  # 消息转化为16进制字符串
        e = int(E, 16)

        d = int(self.private_key, 16)
        k = int(K, 16)

        P1 = self._kg(k, self.ecc_table['g'])

        x = int(P1[0:self.para_len], 16)
        R = ((e + x) % int(self.ecc_table['n'], base=16))
        if R == 0 or R + k == int(self.ecc_table['n'], base=16):
            return None
        d_1 = pow(d + 1, int(self.ecc_table['n'], base=16) - 2, int(self.ecc_table['n'], base=16))
        S = (d_1 * (k + R) - R) % int(self.ecc_table['n'], base=16)
        if S == 0:
            return None
        else:
            return '%064x%064x' % (R, S)

    def encrypt(self, data):
        # 加密函数，data消息(bytes)
        msg = data.hex()  # 消息转化为16进制字符串
        k = func.random_hex(self.para_len)
        C1 = self._kg(int(k, 16), self.ecc_table['g'])
        xy = self._kg(int(k, 16), self.public_key)
        x2 = xy[0:self.para_len]
        y2 = xy[self.para_len:2 * self.para_len]
        ml = len(msg)
        t = sm3.sm3_kdf(xy.encode('utf8'), ml / 2)

        if int(t, 16) == 0:
            return None
        else:
            form = '%%0%dx' % ml
            C2 = form % (int(msg, 16) ^ int(t, 16))
            x = C1[0:self.para_len]
            y = C1[self.para_len:2 * self.para_len]

            C3 = sm3.sm3_hash([
                                  i for i in bytes.fromhex('%s%s%s' % (x2, msg, y2))
                                  ])
            data = C1C3C2()

            data["x"] = Integer(int(x, 16))
            data["y"] = Integer(int(y, 16))
            data["C3"] = OctetString(hexValue=C3)
            data["C2"] = OctetString(hexValue=C2)

            return encode(data)

    def decrypt(self, data):
        C1C3C2_map, _ = decode(data)

        x = "{:064X}".format(int(C1C3C2_map["field-0"]))
        y = "{:064X}".format(int(C1C3C2_map["field-1"]))

        C1 = x + y
        C2 = C1C3C2_map["field-3"].asOctets().hex()
        C3 = C1C3C2_map["field-2"].asOctets().hex()


        len_2 = 2 * self.para_len
        xy = self._kg(int(self.private_key, 16), C1)
        x2 = xy[0:self.para_len]
        y2 = xy[self.para_len:len_2]
        cl = len(C2)
        t = sm3.sm3_kdf(xy.encode('utf8'), cl / 2)
        if int(t, 16) == 0:
            return None
        else:
            form = '%%0%dx' % cl
            M = form % (int(C2, 16) ^ int(t, 16))
            u = sm3.sm3_hash([
                                 i for i in bytes.fromhex('%s%s%s' % (x2, M, y2))
                                 ])
            if u != C3:
                return None
            return bytes.fromhex(M)
