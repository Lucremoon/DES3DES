
from Crypto.Cipher import DES, DES3
from Crypto.Util.Padding import pad, unpad
from binascii import hexlify, unhexlify

# === Parte 1 ===
print("\n--- Parte 1: DES ---")

# 1) DES básico
key1 = unhexlify("133457799BBCDFF1")
data1 = b"HolaMund"
cipher1 = DES.new(key1, DES.MODE_ECB)
ciphered1 = cipher1.encrypt(pad(data1, 8))
print("1.a) Cifrado (DES):", hexlify(ciphered1).decode())

# Descifrado
decipher1 = cipher1.decrypt(ciphered1)
print("1.b) Descifrado:", unpad(decipher1, 8).decode())

# 2) Sensibilidad a la clave
key2 = unhexlify("133457799BBCDFE1")
cipher2 = DES.new(key2, DES.MODE_ECB)
ciphered2 = cipher2.encrypt(pad(data1, 8))
print("2.a) Cifrado con clave modificada:", hexlify(ciphered2).decode())

print("2.b) ¿Difieren los cifrados?", ciphered1 != ciphered2)

# === Parte 2 ===
print("\n--- Parte 2: Modos ECB vs CBC ---")

# Texto con bloques repetidos
key_ecb = unhexlify("AABBCCDDEEFF0011")
iv = unhexlify("1234567890ABCDEF")
data2 = b"ABCDEFGHABCDEFGH"  # 16 bytes

# ECB
cipher_ecb = DES.new(key_ecb, DES.MODE_ECB)
ciphered_ecb = cipher_ecb.encrypt(pad(data2, 8))
print("a) Cifrado ECB:", hexlify(ciphered_ecb).decode())

# CBC
cipher_cbc = DES.new(key_ecb, DES.MODE_CBC, iv)
ciphered_cbc = cipher_cbc.encrypt(pad(data2, 8))
print("b) Cifrado CBC:", hexlify(ciphered_cbc).decode())

# Comparación
print("c) ¿Bloques ECB repetidos?", ciphered_ecb[:8] == ciphered_ecb[8:16])
print("   ¿Bloques CBC repetidos?", ciphered_cbc[:8] == ciphered_cbc[8:16])

# === Parte 3 ===
print("\n--- Parte 3: Triple DES (3DES) ---")

# 1) 3DES con 3 claves diferentes
k1 = unhexlify("0123456789ABCDEF")
k2 = unhexlify("FEDCBA9876543210")
k3 = unhexlify("AABBCCDDEEFF0011")
key_3des = k1 + k2 + k3
data3 = b"Ciberseg"

cipher3 = DES3.new(key_3des, DES3.MODE_ECB)
ciphered3 = cipher3.encrypt(pad(data3, 8))
print("1.a) Cifrado con 3DES EDE3:", hexlify(ciphered3).decode())

# Descifrado
deciphered3 = cipher3.decrypt(ciphered3)
print("1.b) Descifrado:", unpad(deciphered3, 8).decode())

# 2) 3DES con claves iguales (debería ser igual al cifrado DES simple)
print("\n--- Caso Especial 3DES = DES ---")
k_single = unhexlify("0123456789ABCDEF")
key_same = k_single * 3

# 3DES
cipher_3same = DES3.new(key_same, DES3.MODE_ECB)
c_3same = cipher_3same.encrypt(pad(data3, 8))
print("2.a) Cifrado 3DES (K1=K2=K3):", hexlify(c_3same).decode())

# DES simple
cipher_des = DES.new(k_single, DES.MODE_ECB)
c_des = cipher_des.encrypt(pad(data3, 8))
print("2.b) Cifrado DES simple:", hexlify(c_des).decode())

# Comparación
print("2.c) ¿Son iguales?", c_3same == c_des)
