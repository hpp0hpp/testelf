from aes import AES
text = "0123456789"#"cBDw1t5m3WC9vH+9v7zBcHYHc75D1e0mbXuod2yPcqDZ1tImcWCpvtiTv2st+HeZbtzCvNyN32yDc8+937sh+85Cb8cw+/CMcH6NvHeHcI=="
key = "ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv"
iv = "WonrnVkxeIxDcFbv"


aes=AES(key.encode('utf-8'))
encrypted = aes.encrypt_cbc(text.encode('utf-8'), iv.encode('utf-8'))
print(encrypted.hex())
