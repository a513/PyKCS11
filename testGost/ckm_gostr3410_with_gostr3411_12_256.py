#!/usr/bin/env python3

from PyKCS11 import *

mechanism = Mechanism(CKM_GOSTR3410_WITH_GOSTR3411_12_256, None)
mechanism1 = Mechanism(CKM_GOSTR3410, None)
hash_mechanism = Mechanism(CKM_GOSTR3411_12_256, None)
mechanism_3410 = Mechanism(CKM_GOSTR3410, None)
mechanism_gen  = Mechanism(CKM_GOSTR3410_KEY_PAIR_GEN, None)
gostR3410params = [ 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01]
gostR3411params = [0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02]

data = [
        0x61, 0x62, 0x63, 0x64, 0x62, 0x63, 0x64, 0x65,
        0x63, 0x64, 0x65, 0x66, 0x64, 0x65, 0x66, 0x67,
        0x65, 0x66, 0x67, 0x68, 0x66, 0x67, 0x68, 0x69,
        0x67, 0x68, 0x69, 0x6A, 0x68, 0x69, 0x6A, 0x6B,
        0x69, 0x6A, 0x6B, 0x6C, 0x6A, 0x6B, 0x6C, 0x6D,
        0x6B, 0x6C, 0x6D, 0x6E, 0x6C, 0x6D, 0x6E, 0x6F,
        0x6D, 0x6E, 0x6F, 0x70, 0x6E, 0x6F, 0x70, 0x71,
        0x0A
]

data_hash = [
        0xe0, 0x05, 0x24, 0xb6, 0x9d, 0xb2, 0x79, 0xbc,
        0x63, 0xf0, 0xd9, 0x0d, 0x40, 0xe1, 0x82, 0x3d,
        0xd1, 0x9f, 0x7a, 0xd6, 0x49, 0x8e, 0x72, 0x45,
        0xab, 0x21, 0x74, 0x03, 0x70, 0x3a, 0x38, 0x2e,
]

pub_template = [
    (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
    (PyKCS11.CKA_GOSTR3410_PARAMS, gostR3410params),
    (PyKCS11.CKA_GOSTR3411_PARAMS, gostR3411params),
]
priv_template = [
    (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
]

pkcs11 = PyKCS11.PyKCS11Lib()
#Выбираем библиотеку
#Программный токен
lib = '/usr/local/lib64/libls11sw2016.so'
#Для Windows
#lib='C:\Temp\ls11sw2016.dll'
#Облачный токен
#lib = '/usr/local/lib64/libls11cloud.so'
#Аппаратный токен
#lib = '/usr/local/lib64/librtpkcs11ecp_2.0.so'

pkcs11.load(lib)
slot = pkcs11.getSlotList(tokenPresent=True)[0]
session = pkcs11.openSession(slot, PyKCS11.CKF_SERIAL_SESSION)
digestSession = session.digestSession(hash_mechanism)
digestSession.update(data)
digest = digestSession.final()
if (bytes(digest) != bytes(data_hash)):
    print ('Invalid result')
    print (bytes(digest))
    print (bytes(et0))
else:
    print ('OK')

userpin = '01234567'
session.login(userpin)
(pub_key, priv_key) = session.generateKeyPair(
#    pub_template, priv_template, mecha=PyKCS11.MechanismGOSTR3410KEYPAIR512
    pub_template, priv_template, mecha=mechanism_gen
)

signature = session.sign(priv_key, data, mechanism)
print("\nsignature:")
print(bytes(signature).hex())
#К сожалению signUpdate и verifyUpdate не реализовано в __init_.py
result = session.verify(pub_key, data, signature, mechanism)
if (result == True):
    print ('Подпись хорошая 1')
else:
    print ('Подпись плохая 1')
    print (result)
result = session.verify(pub_key, digest, signature, mechanism1)
if (result == True):
    print ('Подпись хорошая 2')
else:
    print ('Подпись плохая 2')
    print (result)
