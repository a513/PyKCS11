#!/usr/bin/env python3

from PyKCS11 import *

#tc26_decc_A_der_oid = b'\x06\x09\x2a\x85\x03\x07\x01\x02\x01\x02\x01'

# тестовые значения мастер-ключа
kMasterKeyData = b'\
\x88\x99\xaa\xbb\xcc\xdd\xee\xff\
\x00\x11\x22\x33\x44\x55\x66\x77\
\xfe\xdc\xba\x98\x76\x54\x32\x10\
\x01\x23\x45\x67\x89\xab\xcd\xef\
'
kGost14CbcSV = b'\
\x12\x34\x56\x78\x90\xab\xce\xf0\
\xa1\xb2\xc3\xd4\xe5\xf0\x01\x12\
\x23\x34\x45\x56\x67\x78\x89\x90\
\x12\x13\x14\x15\x16\x17\x18\x19\
'

# значение открытого текста 
kGost14PlainText = b'\
\x11\x22\x33\x44\x55\x66\x77\x00\
\xff\xee\xdd\xcc\xbb\xaa\x99\x88\
\x00\x11\x22\x33\x44\x55\x66\x77\
\x88\x99\xaa\xbb\xcc\xee\xff\x0a\
\x11\x22\x33\x44\x55\x66\x77\x88\
\x99\xaa\xbb\xcc\xee\xff\x0a\x00\
\x22\x33\x44\x55\x66\x77\x88\x99\
\xaa\xbb\xcc\xee\xff\x0a\x00\x11\
'
# значение шифртекста 
kGost14CbcC_OK = b'\
\x68\x99\x72\xd4\xa0\x85\xfa\x4d\
\x90\xe5\x2e\x3d\x6d\x7d\xcc\x27\
\x28\x26\xe6\x61\xb4\x78\xec\xa6\
\xaf\x1e\x8e\x44\x8d\x5e\xa5\xac\
\xfe\x7b\xab\xf1\xe9\x19\x99\xe8\
\x56\x40\xe8\xb0\xf4\x9d\x90\xd0\
\x16\x76\x88\x06\x5a\x89\x5c\x63\
\x1a\x2d\x9a\x15\x60\xb6\x39\x70\
'

# значение шифртекста
kGost14CbcC =[
        0x68, 0x99, 0x72, 0xd4, 0xa0, 0x85, 0xfa, 0x4d,
        0x90, 0xe5, 0x2e, 0x3d, 0x6d, 0x7d, 0xcc, 0x27,
        0x28, 0x26, 0xe6, 0x61, 0xb4, 0x78, 0xec, 0xa6,
        0xaf, 0x1e, 0x8e, 0x44, 0x8d, 0x5e, 0xa5, 0xac,
        0xfe, 0x7b, 0xab, 0xf1, 0xe9, 0x19, 0x99, 0xe8,
        0x56, 0x40, 0xe8, 0xb0, 0xf4, 0x9d, 0x90, 0xd0,
        0x16, 0x76, 0x88, 0x06, 0x5a, 0x89, 0x5c, 0x63,
        0x1a, 0x2d, 0x9a, 0x15, 0x60, 0xb6, 0x39, 0x70
]



key_template = [
    (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
    (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_KUZNYECHIK),
    (PyKCS11.CKA_VALUE, kMasterKeyData),
    (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
]

#Упаковываем der в hex
#kMasterKeyData_hex = bytes(kMasterKeyData).hex()
#print (kMasterKeyData_hex)
#kMasterKeyData_bin = bytearray.fromhex(kMasterKeyData_hex)
#print (kMasterKeyData)
#print (key_template)
#
#Перевод из hex в der
#cert_der = bytearray.fromhex(cert_der_hex)
#Перевод из binary в hex
#cert_der_hex = bytes(cert_der).hex()
#cert_der_hex = bytes(bytearray.fromhex(cert_der_hex)).hex()

print (kMasterKeyData)

pkcs11 = PyKCS11Lib()
#Выбираем библиотеку
#Программный токен
lib = '/usr/local/lib64/libls11sw2016.so'
#Для Windows
#lib='C:\Temp\ls11sw2016.dll'
#Облачный токен
#lib = '/usr/local/lib64/libls11cloud.so'
#Аппаратный токен
#lib = '/usr/local/lib64/librtpkcs11ecp_2.0.so'

pkcs11.load(lib)  # define environment variable PYKCS11LIB=YourPKCS11Lib

slot = pkcs11.getSlotList(tokenPresent=True)[0]
session = pkcs11.openSession(slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)

pin = "01234567"
session.login(pin, PyKCS11.CKU_USER)

keyh = session.createObject(key_template)
mechanism = PyKCS11.Mechanism(PyKCS11.CKM_KUZNYECHIK_CBC, kGost14CbcSV)

value = session.encrypt(keyh, kGost14PlainText, mechanism)
#value_hex = bytes(value).hex()
#print('"' + value_hex + '"')
#print('"' + bytes(kGost14CbcC).hex() + '"')

print ('================================')
print (value)
print (kGost14CbcC)
print ('================================')

if (bytes(value) != bytes(kGost14CbcC)):
#Сравниваем как массив байтов!!!!
#if (bytearray(value) != kGost14CbcC):
    print ('Error')
else:
    print ('OK')
if (bytes(value).hex() != bytes(kGost14CbcC).hex()):
    print ('Error 1')
else:
    print ('OK 1')

