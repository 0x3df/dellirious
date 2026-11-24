#!/usr/bin/env python3
"""Generate tinyaes.h (decrypt-only, tables verified via pycryptodome) + blobs."""
import os, sys
from Crypto.Cipher import AES  # ground truth for blob encryption

# ---- verified-correct tables (sbox[0:4]=63,7c,77,7b; decrypt(FIPS ct)==FIPS pt) ----
def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80
        a = ((a << 1) & 0xFF) ^ (0x1B if hi else 0)
        b >>= 1
    return p
def ginv(a):
    if a == 0: return 0
    for b in range(1, 256):
        if gmul(a, b) == 1: return b
def affine(b):
    r = b
    for _ in range(4):
        b = ((b << 1) | (b >> 7)) & 0xFF
        r ^= b
    return r ^ 0x63
SBOX = [affine(ginv(x)) for x in range(256)]
assert SBOX[0:4] == [0x63, 0x7c, 0x77, 0x7b]
INV_SBOX = [0]*256
for x, y in enumerate(SBOX): INV_SBOX[y] = x
assert INV_SBOX[0x00] == 0x52

def xtime(x): return ((x << 1) & 0xFF) ^ (0x1B if x & 0x80 else 0)
def expand_key(key):
    rk = list(key); rcon = 1
    for i in range(16, 176, 4):
        t = rk[i-4:i]
        if i % 16 == 0:
            t = [SBOX[t[1]] ^ rcon, SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]]
            rcon = xtime(rcon)
        for j in range(4): rk.append(rk[i-16+j] ^ t[j])
    return rk
def add_rk(st, rk, r): return [b ^ k for b, k in zip(st, rk[r*16:(r+1)*16])]
def inv_shift_rows(st):
    st = st[:]
    for r in range(1, 4):
        row = [st[r + 4*c] for c in range(4)]
        row = row[-r:] + row[:-r]
        for c in range(4): st[r + 4*c] = row[c]
    return st
def inv_sub(st): return [INV_SBOX[b] for b in st]
def inv_mix_columns(st):
    st = st[:]
    for c in range(4):
        col = st[4*c:4*c+4]
        st[4*c+0] = gmul(col[0],14) ^ gmul(col[1],11) ^ gmul(col[2],13) ^ gmul(col[3],9)
        st[4*c+1] = gmul(col[0],9) ^ gmul(col[1],14) ^ gmul(col[2],11) ^ gmul(col[3],13)
        st[4*c+2] = gmul(col[0],13) ^ gmul(col[1],9) ^ gmul(col[2],14) ^ gmul(col[3],11)
        st[4*c+3] = gmul(col[0],11) ^ gmul(col[1],13) ^ gmul(col[2],9) ^ gmul(col[3],14)
    return st
def decrypt_block(rk, block):
    st = add_rk(list(block), rk, 10)
    for r in range(9, 0, -1):
        st = inv_shift_rows(st); st = inv_sub(st); st = add_rk(st, rk, r); st = inv_mix_columns(st)
    st = inv_shift_rows(st); st = inv_sub(st); st = add_rk(st, rk, 0)
    return st

# ground-truth anchor: pycryptodome ct -> FIPS plaintext
key = bytes(range(16))
ct  = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
pt  = bytes.fromhex("00112233445566778899aabbccddeeff")
got = bytes(decrypt_block(expand_key(list(key)), list(ct)))
assert got == pt, f"decrypt anchor FAILED: {got.hex()}"
print("[+] decrypt anchor: FIPS ct -> FIPS pt verified")

# ---- blobs: encrypted by pycryptodome (ground truth) ----
real_key = os.urandom(16)
strings = {
    "BLOB_DEVPATH": "\\\\.\\DBUtil_2_5",
    "BLOB_INF":     "dbutildrv2.inf",
    "BLOB_PSI":     "PsInitialSystemProcess",
    "BLOB_ROOT":    "ROOT\\DBUtilDrv2",
}
cipher = AES.new(bytes(real_key), AES.MODE_ECB)
blobs = {}
for n, s in strings.items():
    b = s.encode()
    b += b"\x00" * ((16 - len(b) % 16) % 16)
    blobs[n] = cipher.encrypt(b)

# sanity: pycryptodome decrypt round trip
for n, s in strings.items():
    back = cipher.decrypt(bytes(blobs[n])).rstrip(b"\x00")
    assert back == s.encode(), n
print("[+] blobs encrypted + round-trip verified via pycryptodome")

# ---- emit C ----
def ctable(name, arr):
    lines = [f"static const unsigned char {name}[256] = {{"]
    for i in range(0, 256, 16):
        lines.append("    " + ", ".join(f"0x{b:02x}" for b in arr[i:i+16]) + ",")
    lines.append("};")
    return "\n".join(lines)
def cblob(name, arr):
    lines = [f"static const unsigned char {name}[{len(arr)}] = {{"]
    for i in range(0, len(arr), 16):
        lines.append("    " + ", ".join(f"0x{b:02x}" for b in arr[i:i+16]) + ",")
    lines.append("};")
    return "\n".join(lines)

header = ('// tinyaes.h - AES-128-ECB decrypt-only, string-sized payloads.\n'
          '// Tables generated from Rijndael first principles; FIPS-197 App. C\n'
          '// known-answer verified at generation time and by test_tinyaes.cpp.\n'
          '#ifndef TINYAES_H\n#define TINYAES_H\n#include <string.h>\n\n'
          + ctable("TINYAES_SBOX", SBOX) + "\n\n" + ctable("TINYAES_INV_SBOX", INV_SBOX) + '''

static unsigned char TinyXtime(unsigned char x)
{
    return (unsigned char)((x << 1) ^ ((x & 0x80) ? 0x1B : 0x00));
}
static unsigned char TinyGmul(unsigned char a, unsigned char b)
{
    unsigned char p = 0;
    for (int i = 0; i < 8; i++)
    {
        if (b & 1) p ^= a;
        unsigned char hi = a & 0x80;
        a = (unsigned char)((a << 1) ^ (hi ? 0x1B : 0x00));
        b >>= 1;
    }
    return p;
}
static void TinyExpandKey(const unsigned char* key, unsigned char* rk)
{
    for (int i = 0; i < 16; i++) rk[i] = key[i];
    unsigned char rcon = 1;
    for (int i = 16; i < 176; i += 4)
    {
        unsigned char t[4] = { rk[i-4], rk[i-3], rk[i-2], rk[i-1] };
        if (i % 16 == 0)
        {
            unsigned char tmp = t[0];
            t[0] = (unsigned char)(TINYAES_SBOX[t[1]] ^ rcon);
            t[1] = TINYAES_SBOX[t[2]];
            t[2] = TINYAES_SBOX[t[3]];
            t[3] = TINYAES_SBOX[tmp];
            rcon = TinyXtime(rcon);
        }
        for (int j = 0; j < 4; j++) rk[i+j] = (unsigned char)(rk[i-16+j] ^ t[j]);
    }
}
static void TinyAddRoundKey(unsigned char* st, const unsigned char* rk, int r)
{
    for (int i = 0; i < 16; i++) st[i] ^= rk[r*16 + i];
}
static void TinyInvShiftRows(unsigned char* st)
{
    // row r rotates RIGHT by r - replicate the 1-rotate r times
    for (int r = 1; r < 4; r++)
    {
        for (int rep = 0; rep < r; rep++)
        {
            unsigned char t = st[r + 12];
            for (int c = 3; c > 0; c--) st[r + 4*c] = st[r + 4*(c-1)];
            st[r] = t;
        }
    }
}
static void TinyInvSubBytes(unsigned char* st)
{
    for (int i = 0; i < 16; i++) st[i] = TINYAES_INV_SBOX[st[i]];
}
static void TinyInvMixColumns(unsigned char* st)
{
    for (int c = 0; c < 4; c++)
    {
        unsigned char a0 = st[4*c], a1 = st[4*c+1], a2 = st[4*c+2], a3 = st[4*c+3];
        st[4*c+0] = (unsigned char)(TinyGmul(a0,14) ^ TinyGmul(a1,11) ^ TinyGmul(a2,13) ^ TinyGmul(a3, 9));
        st[4*c+1] = (unsigned char)(TinyGmul(a0, 9) ^ TinyGmul(a1,14) ^ TinyGmul(a2,11) ^ TinyGmul(a3,13));
        st[4*c+2] = (unsigned char)(TinyGmul(a0,13) ^ TinyGmul(a1, 9) ^ TinyGmul(a2,14) ^ TinyGmul(a3,11));
        st[4*c+3] = (unsigned char)(TinyGmul(a0,11) ^ TinyGmul(a1,13) ^ TinyGmul(a2, 9) ^ TinyGmul(a3,14));
    }
}
static void TinyAes128DecryptBlock(const unsigned char* rk, const unsigned char* in, unsigned char* out)
{
    unsigned char st[16];
    memcpy(st, in, 16);
    TinyAddRoundKey(st, rk, 10);
    for (int r = 9; r >= 1; r--)
    {
        TinyInvShiftRows(st);
        TinyInvSubBytes(st);
        TinyAddRoundKey(st, rk, r);
        TinyInvMixColumns(st);
    }
    TinyInvShiftRows(st);
    TinyInvSubBytes(st);
    TinyAddRoundKey(st, rk, 0);
    memcpy(out, st, 16);
}
static void TinyDecryptString(char* out, const unsigned char* cipher, int blocks,
                              const unsigned char key[16])
{
    unsigned char rk[176];
    TinyExpandKey(key, rk);
    for (int i = 0; i < blocks; i++)
        TinyAes128DecryptBlock(rk, cipher + i*16, (unsigned char*)out + i*16);
    memset(rk, 0, sizeof(rk));
}
#endif // TINYAES_H
''')
open('/Users/lane/maldev/dellicious/src/tinyaes.h', 'w', newline='\r\n').write(header)

blobs_h = "namespace\n{\n" + "\n".join(cblob(n, b) for n, b in blobs.items())
blobs_h += '''

// key stored masked (XOR 0xA5) - never a flat AES key blob in .rdata
static const unsigned char TINY_KEY_MASKED[16] = {
''' + ", ".join(f"0x{b ^ 0xA5:02x}" for b in real_key) + '''
};
static void TinyKey(unsigned char out[16])
{
    for (int i = 0; i < 16; i++) out[i] = (unsigned char)(TINY_KEY_MASKED[i] ^ 0xA5);
}
}
'''
open('/tmp/dellicious_blobs.h', 'w', newline='\r\n').write(blobs_h)

# test_tinyaes.cpp with the CORRECT vectors
test_parts = []
for idx, (n, s) in enumerate(strings.items(), 1):
    test_parts.append(f'''    {{
        unsigned char k{idx}[16], o{idx}[{len(blobs[n])}];
        TinyKey(k{idx});
        TinyDecryptString((char*)o{idx}, {n}, {len(blobs[n])//16}, k{idx});
        if (strcmp((char*)o{idx}, "{s.replace(chr(92), chr(92)*2)}") != 0) {{ printf("{n} FAIL\\n"); return 1; }}
        printf("{n}: PASS (%s)\\n", o{idx});
    }}''')
test = '''// test_tinyaes.cpp - host verification of tinyaes.h (FIPS-197 App. C + blobs)
#include <cstdio>
#include <cstring>
#include "tinyaes.h"

int main()
{
    unsigned char rk[176], key[16], out[16], in[16];
    for (int i = 0; i < 16; i++) { key[i] = (unsigned char)i; in[i] = (unsigned char)i; }
    TinyExpandKey(key, rk);
    unsigned char pt[16] = { 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff };
    unsigned char fips[16] = { 0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a };
    TinyAes128DecryptBlock(rk, fips, out);
    for (int i = 0; i < 16; i++) if (out[i] != pt[i]) { printf("FIPS FAIL\\n"); return 1; }
    printf("FIPS-197 App C: PASS\\n");
''' + "\n".join(test_parts) + '''
    printf("ALL PASS\\n");
    return 0;
}
'''
open('/Users/lane/maldev/dellicious/test_tinyaes.cpp', 'w', newline='\r\n').write(test)
print("[+] tinyaes.h + blobs + test generated")
