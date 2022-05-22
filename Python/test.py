
import aes_class

crypto = aes_class.AES("0123456789abcdef", "NOPAD")

arr = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]

crypto.EncryptStream(arr)