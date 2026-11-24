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
    {
        unsigned char k5[16], o5[16];
        TinyKey(k5);
        TinyDecryptString((char*)o5, BLOB_CSA, 1, k5);
        if (strcmp((char*)o5, "csagent.sys") != 0) { printf("BLOB_CSA FAIL\n"); return 1; }
        printf("BLOB_CSA: PASS (%s)\n", o5);
    }
    {
        unsigned char k6[16], o6[16];
        TinyKey(k6);
        TinyDecryptString((char*)o6, BLOB_CSD, 1, k6);
        if (strcmp((char*)o6, "CrowdStrike") != 0) { printf("BLOB_CSD FAIL\n"); return 1; }
        printf("BLOB_CSD: PASS (%s)\n", o6);
    }
    {
        unsigned char k7[16], o7[32];
        TinyKey(k7);
        TinyDecryptString((char*)o7, BLOB_PPN2, 2, k7);
        if (strcmp((char*)o7, "PspCreateProcessNotifyRoutine") != 0) { printf("BLOB_PPN2 FAIL\n"); return 1; }
        printf("BLOB_PPN2: PASS (%s)\n", o7);
    }
    {
        unsigned char k8[16], o8[32];
        TinyKey(k8);
        TinyDecryptString((char*)o8, BLOB_PTN2, 2, k8);
        if (strcmp((char*)o8, "PspCreateThreadNotifyRoutine") != 0) { printf("BLOB_PTN2 FAIL\n"); return 1; }
        printf("BLOB_PTN2: PASS (%s)\n", o8);
    }
    {
        unsigned char k9[16], o9[32];
        TinyKey(k9);
        TinyDecryptString((char*)o9, BLOB_PPN, 2, k9);
        if (strcmp((char*)o9, "PspProcessNotifyRoutine") != 0) { printf("BLOB_PPN FAIL\n"); return 1; }
        printf("BLOB_PPN: PASS (%s)\n", o9);
    }
    {
        unsigned char k10[16], o10[32];
        TinyKey(k10);
        TinyDecryptString((char*)o10, BLOB_PTN, 2, k10);
        if (strcmp((char*)o10, "PspThreadNotifyRoutine") != 0) { printf("BLOB_PTN FAIL\n"); return 1; }
        printf("BLOB_PTN: PASS (%s)\n", o10);
    }
    {
        unsigned char k11[16], o11[32];
        TinyKey(k11);
        TinyDecryptString((char*)o11, BLOB_LIN, 2, k11);
        if (strcmp((char*)o11, "PspLoadImageNotifyRoutine") != 0) { printf("BLOB_LIN FAIL\n"); return 1; }
        printf("BLOB_LIN: PASS (%s)\n", o11);
    }
    {
        unsigned char k12[16], o12[32];
        TinyKey(k12);
        TinyDecryptString((char*)o12, BLOB_CMH, 2, k12);
        if (strcmp((char*)o12, "CmCallbackListHead") != 0) { printf("BLOB_CMH FAIL\n"); return 1; }
        printf("BLOB_CMH: PASS (%s)\n", o12);
    }
    {
        unsigned char k13[16], o13[32];
        TinyKey(k13);
        TinyDecryptString((char*)o13, BLOB_CBH2, 2, k13);
        if (strcmp((char*)o13, "CallbackListHead") != 0) { printf("BLOB_CBH2 FAIL\n"); return 1; }
        printf("BLOB_CBH2: PASS (%s)\n", o13);
    }
    {
        unsigned char k14[16], o14[32];
        TinyKey(k14);
        TinyDecryptString((char*)o14, BLOB_CBH3, 2, k14);
        if (strcmp((char*)o14, "CmCallBackListHead") != 0) { printf("BLOB_CBH3 FAIL\n"); return 1; }
        printf("BLOB_CBH3: PASS (%s)\n", o14);
    }
    {
        unsigned char k15[16], o15[32];
        TinyKey(k15);
        TinyDecryptString((char*)o15, BLOB_CBCT, 2, k15);
        if (strcmp((char*)o15, "CmpCallBackCount") != 0) { printf("BLOB_CBCT FAIL\n"); return 1; }
        printf("BLOB_CBCT: PASS (%s)\n", o15);
    }
    printf("ALL PASS\n");
    return 0;
}
