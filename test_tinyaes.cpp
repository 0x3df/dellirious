// test_tinyaes.cpp - host verification of tinyaes.h (FIPS-197 App. C + blobs)
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
    for (int i = 0; i < 16; i++) if (out[i] != pt[i]) { printf("FIPS FAIL\n"); return 1; }
    printf("FIPS-197 App C: PASS\n");
    {
        unsigned char k1[16], o1[16];
        TinyKey(k1);
        TinyDecryptString((char*)o1, BLOB_DEVPATH, 1, k1);
        if (strcmp((char*)o1, "\\\\.\\DBUtil_2_5") != 0) { printf("BLOB_DEVPATH FAIL\n"); return 1; }
        printf("BLOB_DEVPATH: PASS (%s)\n", o1);
    }
    {
        unsigned char k2[16], o2[16];
        TinyKey(k2);
        TinyDecryptString((char*)o2, BLOB_INF, 1, k2);
        if (strcmp((char*)o2, "dbutildrv2.inf") != 0) { printf("BLOB_INF FAIL\n"); return 1; }
        printf("BLOB_INF: PASS (%s)\n", o2);
    }
    {
        unsigned char k3[16], o3[32];
        TinyKey(k3);
        TinyDecryptString((char*)o3, BLOB_PSI, 2, k3);
        if (strcmp((char*)o3, "PsInitialSystemProcess") != 0) { printf("BLOB_PSI FAIL\n"); return 1; }
        printf("BLOB_PSI: PASS (%s)\n", o3);
    }
    {
        unsigned char k4[16], o4[16];
        TinyKey(k4);
        TinyDecryptString((char*)o4, BLOB_ROOT, 1, k4);
        if (strcmp((char*)o4, "ROOT\\DBUtilDrv2") != 0) { printf("BLOB_ROOT FAIL\n"); return 1; }
        printf("BLOB_ROOT: PASS (%s)\n", o4);
    }
    printf("ALL PASS\n");
    return 0;
}
