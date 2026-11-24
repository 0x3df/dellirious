# dellirious

Fork of [jbaines-r7/dellicious](https://github.com/jbaines-r7/dellicious).
All credit for the original tool and research to James Baines
([@jbaines-r7](https://github.com/jbaines-r7)) / Rapid7.

**Changes vs upstream:**

- Windows 11 26100/26200 support - EPROCESS offsets resolve from the real
  kernel symbols (msdl PDB + dbghelp) and are anchor-validated before use
- `-S`/`-R <pid>` - PPL-protect self, then suspend/resume the target process
  via `NtSuspendProcess`/`NtResumeProcess` (telemetry stops, process alive;
  `-R` undoes)
- `-t/--status` - DBUtil device diagnostic mode
- MSVC target - Dbghelp/Urlmon/Psapi linked in all configs
- String anchors (device path, inf name, kernel symbol names) stored
  AES-encrypted, decrypted at runtime

## Build

    msbuild dellicious.sln /p:Configuration=Release /p:Platform=x64

or

    x86_64-w64-mingw32-windres -I src src/dellirious.rc -O coff -o res.o
    x86_64-w64-mingw32-g++ -std=c++17 src/main.cpp res.o -Isrc -o dbutil_diag.exe         -lnewdev -lpsapi -ldbghelp -lurlmon -lole32 -lsetupapi

## Usage

    dbutil_diag.exe -t                              # device status
    dbutil_diag.exe -p <pid> -e 0|1 -d <dir>        # protect/unprotect a process
    dbutil_diag.exe -S <pid,pid,...> -d <dir>       # suspend the set
    dbutil_diag.exe -R <pid,pid,...> -d <dir>       # resume the set

Admin required. `-d` = directory with `dbutildrv2.inf`/`.cat`/`.sys`; the
driver is installed, used, and removed on every run. MIT - see upstream.
