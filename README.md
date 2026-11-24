# dellirious

Fork of [jbaines-r7/dellicious](https://github.com/jbaines-r7/dellicious).
All credit for the original tool and research to James Baines
([@jbaines-r7](https://github.com/jbaines-r7)) / Rapid7.

**Changes vs upstream:**

- Kernel notification-callback audit (`-K`): enumerates the process/thread/
  image-load notify arrays and the registry callback lists, flags every
  entry owned by a target suite (a named driver plus everything under its
  vendor driver directory), and can remove those entries on demand and put
  them back byte-for-byte
  - `list` - read-only audit
  - `disable` - EX_FAST_REF slots zeroed, registry list nodes unlinked;
    every removal recorded in a boot-bound state file
  - `restore` - replays the state file, skipping records the kernel has
    since invalidated (re-registration)
  - `verify` - zero-dereference blind check against the state file
- Storage addresses resolve from the real kernel symbols (msdl PDB +
  dbghelp) and are range-validated before any write; 26xxx symbol drift
  handled (PspCreate*NotifyRoutine names, SymEnumSymbols retry, registry
  head self-validated against CmpCallBackCount via a neighborhood sweep)
- Kernel base located without trusting user-mode enumeration: fixed-address
  debugger-data chain, raw module list as fallback
- No on-disk file access anywhere in the audit path: in-kernel
  loaded-module walk plus read-primitive PE validation for every range
- Dereference-exposure controls: pool-alignment gates on every walked
  node, sweep candidates require driver-image content in their first
  (proven-mapped) node before any further walk
- `-t/--status` - DBUtil device diagnostic mode
- `-v/--verbose` - full audit output (default output is need-to-know)
- MSVC target - Dbghelp/Urlmon/Psapi linked in all configs
- String anchors (device path, inf name, kernel symbol names, target
  module/directory names) stored AES-encrypted, decrypted at runtime

## Build

    msbuild dellicious.sln /p:Configuration=Release /p:Platform=x64

or

    x86_64-w64-mingw32-windres -I src src/dellirious.rc -O coff -o res.o
    x86_64-w64-mingw32-g++ -std=c++17 src/main.cpp res.o -Isrc -o dbutil_diag.exe -lnewdev -lpsapi -ldbghelp -lurlmon -lole32 -lsetupapi

## Usage

    dbutil_diag.exe -t                              # device status
    dbutil_diag.exe -K list    -d <dir>             # audit notify callbacks, flag suite-owned entries
    dbutil_diag.exe -K disable -d <dir>             # remove suite-owned callbacks (state saved)
    dbutil_diag.exe -K verify  -d <dir>             # zero-deref blind check against the state file
    dbutil_diag.exe -K restore -d <dir>             # put the removed entries back
    dbutil_diag.exe -K list -v -d <dir>             # full audit output

Windows target: 26100/26200 only - other builds are refused before the
driver is touched. Admin required. `-d` = directory with
`dbutildrv2.inf`/`.cat`/`.sys`; the
driver is installed, used, and removed on every run. `-K` state lives in
`%TEMP%\dbutil_diag.state` and is boot-bound. During an active disable use
`verify` for the blind check - full `list` re-enumeration can dereference
responder-freed blocks. Boundary: `-K` covers the four notify channels, not
object callbacks, minifilters, or ETW; a kernel-side responder that
re-registers between `disable` and `restore` makes its records stale -
restore detects and skips them. MIT - see upstream.
