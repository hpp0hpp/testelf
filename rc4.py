class RC4:
    def __init__(self, key: bytes):
        """
        初始化 RC4 类
        :param key: 密钥，字节类型
        """
        self.key = key
        self.s = list(range(256))  # 初始化 S 数组
        self._ksa()  # 执行密钥调度算法

    def _ksa(self):
        """
        密钥调度算法 (Key Scheduling Algorithm, KSA)
        """
        j = 0
        key_length = len(self.key)
        for i in range(256):
            j = (j + self.s[i] + self.key[i % key_length]) % 256
            self.s[i], self.s[j] = self.s[j], self.s[i]  # 交换 S[i] 和 S[j]
        print(''.join(hex(i)[2:] for i in self.s))
    def _prga(self):
        """
        伪随机数生成算法 (Pseudo-Random Generation Algorithm, PRGA)
        :yield: 生成的伪随机字节
        """
        i = j = 0
        while True:
            i = (i + 1) % 256
            j = (j + self.s[i]) % 256
            self.s[i], self.s[j] = self.s[j], self.s[i]  # 交换 S[i] 和 S[j]
            res= self.s[(self.s[i] + self.s[j]) % 256]
            print(hex(res))
            yield res

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        加密明文
        :param plaintext: 明文，字节类型
        :return: 密文，字节类型
        """
        keystream = self._prga()
        #print keystream
        
        return bytes([p ^ next(keystream) for p in plaintext])

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        解密密文
        :param ciphertext: 密文，字节类型
        :return: 明文，字节类型
        """
        # RC4 的加密和解密过程相同
        return self.encrypt(ciphertext)
def hex_to_bytes(hex_str):
    return bytes.fromhex(hex_str)

if __name__ == "__main__":
    key = b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv"
    rc4 = RC4(key)
    plaintext = hex_to_bytes('ab9fa36b16e887d48ce2376be578a6db')
    ciphertext = rc4.encrypt(plaintext)
    print("密文:", ciphertext.hex())
    print('73cc96feb60830cfe31a00c7922b7c92')