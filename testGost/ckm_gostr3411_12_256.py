#!/usr/bin/env python3

from PyKCS11 import *

#mechanism_desc = { CKM_GOSTR3411_12_256, NULL, 0 };

data0 = "87654321";
et0   = [
        0x50, 0x9b, 0xf3, 0x08, 0x11, 0x16, 0x60, 0x22,
        0xd0, 0x72, 0x1a, 0x2d, 0x11, 0x57, 0x2a, 0x98,
        0x89, 0x4a, 0x81, 0xa8, 0xfb, 0x86, 0x70, 0x02,
        0xa5, 0xc2, 0x8e, 0x19, 0x53, 0xec, 0x42, 0xa7,
]
data1 = "Suppose the original message has length = 50 bytes"
et1 = [
        0xa3, 0xed, 0x85, 0x32, 0x2e, 0x1a, 0x14, 0x79,
        0xb6, 0x05, 0xa7, 0x52, 0xb1, 0xd4, 0x87, 0xfd,
        0x13, 0x88, 0x63, 0xaa, 0x1e, 0xa6, 0x7a, 0x91,
        0xe1, 0x57, 0xaa, 0x53, 0xfc, 0xe7, 0x96, 0xf3,
]
data2 = [
        0xb8, 0xe0, 0x45, 0x82, 0x09, 0x28, 0x55, 0xdc,
        0x54, 0x59, 0xca, 0x6b, 0xf8, 0x42, 0xa9, 0x21,
        0xb8, 0xef, 0xa7, 0x96, 0x8b, 0x09, 0xea, 0x0e,
        0xd5, 0xc3, 0xdf, 0x8c, 0xaf, 0x8a, 0x5e, 0x44,
]
et2 = [
        0x42, 0x22, 0x71, 0x8a, 0x1a, 0xa7, 0x67, 0x43,
        0xfd, 0x42, 0x45, 0x01, 0x9c, 0xc2, 0xc8, 0x1e,
        0xb4, 0x55, 0x0d, 0x37, 0x0e, 0x17, 0x22, 0x59,
        0x99, 0xc0, 0xd7, 0x00, 0x8b, 0xd8, 0x9f, 0xd3,
]

data3 = [
        0x30, 0x82, 0x03, 0x9c, 0xa0, 0x03, 0x02, 0x01,
        0x02, 0x02, 0x10, 0x3a, 0xc3, 0xb8, 0xac, 0xec,
        0xfb, 0xd7, 0xae, 0x28, 0xb5, 0x92, 0x9f, 0xd2,
        0xec, 0x4c, 0xf3, 0x30, 0x08, 0x06, 0x06, 0x2a,
        0x85, 0x03, 0x02, 0x02, 0x03, 0x30, 0x81, 0xec,
        0x31, 0x19, 0x30, 0x17, 0x06, 0x09, 0x2a, 0x86,
        0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16,
        0x0a, 0x67, 0x64, 0x75, 0x63, 0x40, 0x63, 0x61,
        0x2e, 0x72, 0x75, 0x31, 0x0b, 0x30, 0x09, 0x06,
        0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x52, 0x55,
        0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04,
        0x07, 0x0c, 0x0c, 0xd0, 0x9c, 0xd0, 0xbe, 0xd1,
        0x81, 0xd0, 0xba, 0xd0, 0xb2, 0xd0, 0xb0, 0x31,
        0x54, 0x30, 0x52, 0x06, 0x03, 0x55, 0x04, 0x0a,
        0x0c, 0x4b, 0xd0, 0x93, 0xd0, 0xbb, 0xd0, 0xb0,
        0xd0, 0xb2, 0xd0, 0xbd, 0xd1, 0x8b, 0xd0, 0xb9,
        0x20, 0xd0, 0x94, 0xd0, 0xbe, 0xd0, 0xb2, 0xd0,
        0xb5, 0xd1, 0x80, 0xd0, 0xb5, 0xd0, 0xbd, 0xd0,
        0xbd, 0xd1, 0x8b, 0xd0, 0xb9, 0x20, 0xd0, 0xa3,
        0xd0, 0xb4, 0xd0, 0xbe, 0xd1, 0x81, 0xd1, 0x82,
        0xd0, 0xbe, 0xd0, 0xb2, 0xd0, 0xb5, 0xd1, 0x80,
        0xd1, 0x8f, 0xd1, 0x8e, 0xd1, 0x89, 0xd0, 0xb8,
        0xd0, 0xb9, 0x20, 0xd0, 0xa6, 0xd0, 0xb5, 0xd0,
        0xbd, 0xd1, 0x82, 0xd1, 0x80, 0x31, 0x2c, 0x30,
        0x2a, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x23,
        0xd0, 0xa6, 0xd0, 0xb5, 0xd0, 0xbd, 0xd1, 0x82,
        0xd1, 0x80, 0x20, 0xd0, 0xa1, 0xd0, 0xb5, 0xd1,
        0x80, 0xd1, 0x82, 0xd0, 0xb8, 0xd1, 0x84, 0xd0,
        0xb8, 0xd0, 0xba, 0xd0, 0xb0, 0xd1, 0x86, 0xd0,
        0xb8, 0xd0, 0xb8, 0x31, 0x27, 0x30, 0x25, 0x06,
        0x03, 0x55, 0x04, 0x03, 0x0c, 0x1e, 0xd0, 0x93,
        0xd0, 0x94, 0xd0, 0xa3, 0xd0, 0xa6, 0x20, 0xd0,
        0xa1, 0xd1, 0x82, 0xd0, 0xb0, 0xd0, 0xbd, 0xd0,
        0xb4, 0xd0, 0xb0, 0xd1, 0x80, 0xd1, 0x82, 0x20,
        0xd0, 0xa3, 0xd0, 0xa6, 0x30, 0x1e, 0x17, 0x0d,
        0x30, 0x34, 0x30, 0x31, 0x30, 0x39, 0x31, 0x32,
        0x33, 0x33, 0x32, 0x39, 0x5a, 0x17, 0x0d, 0x31,
        0x34, 0x30, 0x31, 0x30, 0x36, 0x31, 0x32, 0x33,
        0x33, 0x32, 0x39, 0x5a, 0x30, 0x81, 0xec, 0x31,
        0x19, 0x30, 0x17, 0x06, 0x09, 0x2a, 0x86, 0x48,
        0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x0a,
        0x67, 0x64, 0x75, 0x63, 0x40, 0x63, 0x61, 0x2e,
        0x72, 0x75, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
        0x55, 0x04, 0x06, 0x13, 0x02, 0x52, 0x55, 0x31,
        0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x07,
        0x0c, 0x0c, 0xd0, 0x9c, 0xd0, 0xbe, 0xd1, 0x81,
        0xd0, 0xba, 0xd0, 0xb2, 0xd0, 0xb0, 0x31, 0x54,
        0x30, 0x52, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
        0x4b, 0xd0, 0x93, 0xd0, 0xbb, 0xd0, 0xb0, 0xd0,
        0xb2, 0xd0, 0xbd, 0xd1, 0x8b, 0xd0, 0xb9, 0x20,
        0xd0, 0x94, 0xd0, 0xbe, 0xd0, 0xb2, 0xd0, 0xb5,
        0xd1, 0x80, 0xd0, 0xb5, 0xd0, 0xbd, 0xd0, 0xbd,
        0xd1, 0x8b, 0xd0, 0xb9, 0x20, 0xd0, 0xa3, 0xd0,
        0xb4, 0xd0, 0xbe, 0xd1, 0x81, 0xd1, 0x82, 0xd0,
        0xbe, 0xd0, 0xb2, 0xd0, 0xb5, 0xd1, 0x80, 0xd1,
        0x8f, 0xd1, 0x8e, 0xd1, 0x89, 0xd0, 0xb8, 0xd0,
        0xb9, 0x20, 0xd0, 0xa6, 0xd0, 0xb5, 0xd0, 0xbd,
        0xd1, 0x82, 0xd1, 0x80, 0x31, 0x2c, 0x30, 0x2a,
        0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x23, 0xd0,
        0xa6, 0xd0, 0xb5, 0xd0, 0xbd, 0xd1, 0x82, 0xd1,
        0x80, 0x20, 0xd0, 0xa1, 0xd0, 0xb5, 0xd1, 0x80,
        0xd1, 0x82, 0xd0, 0xb8, 0xd1, 0x84, 0xd0, 0xb8,
        0xd0, 0xba, 0xd0, 0xb0, 0xd1, 0x86, 0xd0, 0xb8,
        0xd0, 0xb8, 0x31, 0x27, 0x30, 0x25, 0x06, 0x03,
        0x55, 0x04, 0x03, 0x0c, 0x1e, 0xd0, 0x93, 0xd0,
        0x94, 0xd0, 0xa3, 0xd0, 0xa6, 0x20, 0xd0, 0xa1,
        0xd1, 0x82, 0xd0, 0xb0, 0xd0, 0xbd, 0xd0, 0xb4,
        0xd0, 0xb0, 0xd1, 0x80, 0xd1, 0x82, 0x20, 0xd0,
        0xa3, 0xd0, 0xa6, 0x30, 0x63, 0x30, 0x1c, 0x06,
        0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x13, 0x30,
        0x12, 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02,
        0x23, 0x01, 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02,
        0x02, 0x1e, 0x01, 0x03, 0x43, 0x00, 0x04, 0x40,
        0x50, 0xab, 0x7f, 0xc4, 0xcc, 0x3d, 0xd0, 0xe2,
        0xdd, 0x86, 0xda, 0x19, 0x6b, 0x14, 0x8c, 0x78,
        0xd9, 0xca, 0x58, 0x67, 0x62, 0xf3, 0xb7, 0xba,
        0x7b, 0x2a, 0xda, 0xc1, 0x9c, 0x3f, 0x87, 0xeb,
        0xf1, 0xdc, 0xaf, 0x35, 0xad, 0x2d, 0xe1, 0xca,
        0xed, 0xc1, 0x8b, 0x82, 0xde, 0xa0, 0x8b, 0x95,
        0xdd, 0xa2, 0xac, 0x46, 0x6a, 0x8e, 0xce, 0x5d,
        0x5a, 0x16, 0xba, 0x03, 0x29, 0x72, 0x38, 0x27,
        0xa3, 0x82, 0x01, 0x14, 0x30, 0x82, 0x01, 0x10,
        0x30, 0x5a, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x01,
        0x01, 0xff, 0x04, 0x50, 0x30, 0x4e, 0x81, 0x0b,
        0x67, 0x64, 0x75, 0x63, 0x63, 0x40, 0x75, 0x63,
        0x2e, 0x72, 0x75, 0xa4, 0x3f, 0x30, 0x3d, 0x31,
        0x3b, 0x30, 0x39, 0x06, 0x03, 0x55, 0x04, 0x03,
        0x0c, 0x32, 0xd0, 0x9f, 0xd0, 0xb5, 0xd1, 0x80,
        0xd0, 0xb2, 0xd0, 0xbe, 0xd0, 0xb5, 0x20, 0xd0,
        0xa3, 0xd0, 0xbf, 0xd0, 0xbe, 0xd0, 0xbb, 0xd0,
        0xbd, 0xd0, 0xbe, 0xd0, 0xbc, 0xd0, 0xbe, 0xd1,
        0x87, 0xd0, 0xb5, 0xd0, 0xbd, 0xd0, 0xbd, 0xd0,
        0xbe, 0xd0, 0xb5, 0x20, 0xd0, 0x9b, 0xd0, 0xb8,
        0xd1, 0x86, 0xd0, 0xbe, 0x30, 0x0f, 0x06, 0x03,
        0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x05,
        0x03, 0x03, 0x07, 0xc6, 0x00, 0x30, 0x0f, 0x06,
        0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04,
        0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x1d,
        0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04,
        0x14, 0xb1, 0x6e, 0x0e, 0xa4, 0x40, 0xbc, 0xf0,
        0xd9, 0xb6, 0xf7, 0xef, 0xfa, 0xf0, 0x3d, 0xa1,
        0x0c, 0xd2, 0x8f, 0xf1, 0xb6, 0x30, 0x71, 0x06,
        0x03, 0x55, 0x1d, 0x1f, 0x04, 0x6a, 0x30, 0x68,
        0x30, 0x66, 0xa0, 0x64, 0xa0, 0x62, 0x86, 0x60,
        0x6c, 0x64, 0x61, 0x70, 0x3a, 0x2f, 0x2f, 0x31,
        0x39, 0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x36,
        0x38, 0x2e, 0x37, 0x30, 0x2f, 0x6f, 0x3d, 0x72,
        0x6f, 0x6f, 0x74, 0x2c, 0x63, 0x3d, 0x72, 0x75,
        0x3f, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69,
        0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x76, 0x6f,
        0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4c, 0x69,
        0x73, 0x74, 0x3f, 0x62, 0x61, 0x73, 0x65, 0x3f,
        0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x63, 0x6c,
        0x61, 0x73, 0x73, 0x3d, 0x63, 0x52, 0x4c, 0x44,
        0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74,
        0x69, 0x6f, 0x6e, 0x50, 0x6f, 0x69, 0x6e, 0x74
]
et3 = [
        0xc7, 0x64, 0xc9, 0x1a, 0xc5, 0xcd, 0x56, 0x84,
        0x47, 0xab, 0x2f, 0x9a, 0x6b, 0x9e, 0xc8, 0x69,
        0x18, 0x7f, 0x13, 0x72, 0x8f, 0x4c, 0x8e, 0xb0,
        0x30, 0xc8, 0x91, 0xfd, 0x0d, 0x10, 0x73, 0xb0,
]
data6 = [
        0x61, 0x62, 0x63, 0x64, 0x62, 0x63, 0x64, 0x65,
        0x63, 0x64, 0x65, 0x66, 0x64, 0x65, 0x66, 0x67,
        0x65, 0x66, 0x67, 0x68, 0x66, 0x67, 0x68, 0x69,
        0x67, 0x68, 0x69, 0x6A, 0x68, 0x69, 0x6A, 0x6B,
        0x69, 0x6A, 0x6B, 0x6C, 0x6A, 0x6B, 0x6C, 0x6D,
        0x6B, 0x6C, 0x6D, 0x6E, 0x6C, 0x6D, 0x6E, 0x6F,
        0x6D, 0x6E, 0x6F, 0x70, 0x6E, 0x6F, 0x70, 0x71,
        0x0A
]
et6 = [
        0xe0, 0x05, 0x24, 0xb6, 0x9d, 0xb2, 0x79, 0xbc,
        0x63, 0xf0, 0xd9, 0x0d, 0x40, 0xe1, 0x82, 0x3d,
        0xd1, 0x9f, 0x7a, 0xd6, 0x49, 0x8e, 0x72, 0x45,
        0xab, 0x21, 0x74, 0x03, 0x70, 0x3a, 0x38, 0x2e,
]
# Примеры из ГОСТ Р 34.11-2012:
M1 = [
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
        0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31,
        0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32,
]
et1_32 = [
        0x9d, 0x15, 0x1e, 0xef, 0xd8, 0x59, 0x0b, 0x89,
        0xda, 0xa6, 0xba, 0x6c, 0xb7, 0x4a, 0xf9, 0x27,
        0x5d, 0xd0, 0x51, 0x02, 0x6b, 0xb1, 0x49, 0xa4,
        0x52, 0xfd, 0x84, 0xe5, 0xe5, 0x7b, 0x55, 0x00,
]
M2 = [
        0xd1, 0xe5, 0x20, 0xe2, 0xe5, 0xf2, 0xf0, 0xe8,
        0x2c, 0x20, 0xd1, 0xf2, 0xf0, 0xe8, 0xe1, 0xee,
        0xe6, 0xe8, 0x20, 0xe2, 0xed, 0xf3, 0xf6, 0xe8,
        0x2c, 0x20, 0xe2, 0xe5, 0xfe, 0xf2, 0xfa, 0x20,
        0xf1, 0x20, 0xec, 0xee, 0xf0, 0xff, 0x20, 0xf1,
        0xf2, 0xf0, 0xe5, 0xeb, 0xe0, 0xec, 0xe8, 0x20,
        0xed, 0xe0, 0x20, 0xf5, 0xf0, 0xe0, 0xe1, 0xf0,
        0xfb, 0xff, 0x20, 0xef, 0xeb, 0xfa, 0xea, 0xfb,
        0x20, 0xc8, 0xe3, 0xee, 0xf0, 0xe5, 0xe2, 0xfb,
]
et2_32 = [
        0x9d, 0xd2, 0xfe, 0x4e, 0x90, 0x40, 0x9e, 0x5d,
        0xa8, 0x7f, 0x53, 0x97, 0x6d, 0x74, 0x05, 0xb0,
        0xc0, 0xca, 0xc6, 0x28, 0xfc, 0x66, 0x9a, 0x74,
        0x1d, 0x50, 0x06, 0x3c, 0x55, 0x7e, 0x8f, 0x50,
]
# Digest of NULL message, 256 bits, little-endian.
et0_32 = [
        0x3f, 0x53, 0x9a, 0x21, 0x3e, 0x97, 0xc8, 0x02,
        0xcc, 0x22, 0x9d, 0x47, 0x4c, 0x6a, 0xa3, 0x2a,
        0x82, 0x5a, 0x36, 0x0b, 0x2a, 0x93, 0x3a, 0x94,
        0x9f, 0xd9, 0x25, 0x20, 0x8d, 0x9c, 0xe1, 0xbb
]
keyval_33 = [
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34,
        0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32,
        0x0A
]
keyval_33_hash = [
        0x72, 0xc3, 0x40, 0xc5, 0x8f, 0xbb, 0x9d, 0x91,
        0xdf, 0x95, 0x7c, 0xff, 0x0a, 0x87, 0xaa, 0x45,
        0xde, 0xd3, 0xb9, 0x78, 0x12, 0xe8, 0x41, 0xc9,
        0xd4, 0x97, 0x7f, 0xd0, 0xe2, 0xd8, 0xea, 0xb4
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
mechanism = Mechanism(CKM_GOSTR3411_12_256, None)
#Test 1
digest = session.digest(data0, mechanism)
if (bytes(digest) != bytes(et0)):
    print ('Invalid result')
    print (bytes(digest))
    print (bytes(et0))
else:
    print ('OK')

#Test 2
digestSession = session.digestSession(mechanism)
digestSession.update(data0)
digest = digestSession.final()
if (bytes(digest) != bytes(et0)):
    print ('Invalid result')
    print (bytes(digest))
    print (bytes(et0))
else:
    print ('OK')
#Test 3
digestSession = session.digestSession(mechanism)
digestSession.update(data3)
digest = digestSession.final()
if (bytes(digest) != bytes(et3)):
    print ('Invalid result 1')
    print (bytes(digest))
    print (bytes(et0))
else:
    print ('OK 1')
#Test 4
digestSession = session.digestSession(mechanism)
digestSession.update(bytes(data3)[0:39])
print (bytes(data3[0:39]).hex())
len = len(bytes(data3))
print(len)
digestSession.update(bytes(data3)[39:len])
print (bytes(data3[39:len]).hex())
digest = digestSession.final()
if (bytes(digest) != bytes(et3)):
    print ('Invalid result 2')
    print (bytes(digest))
    print (bytes(et0))
else:
    print ('OK 2')
