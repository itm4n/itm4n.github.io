---
title: "The End of PPLdump" 
layout: "post"
categories: [ "Patch Analysis" ]
tags: [ "Research", "Patch Analysis" ]
---

A few days ago, an [issue](https://github.com/itm4n/PPLdump/issues/12) was opened for [PPLdump](https://github.com/itm4n/PPLdump) on GitHub, stating that it no longer worked on Windows 10 21H2 Build 19044.1826. I was skeptical at first so I fired up a new VM and started investigating. Here is what I found...


## PPLdump in a nutshell

If you are reading this, I would assume that you already know what PPLdump is and what it does. But just in case you do not, here is a very brief summary.

[PPLdump](https://github.com/itm4n/PPLdump) is a tool written in C/C++ that implements a _Userland_ exploit for injecting arbitrary code into a PPL as an administrator. This technique is one of the many findings of thorough research conducted by Alex Ionescu and James Forshaw about Protected Processes (PPs and PPLs).

As a reminder, it works like this:

1. The API `DefineDosDevice` is invoked to trick the CSRSS service into creating a Symbolic Link in `\KnownDlls` that points to an arbitrary location.
2. A new Section object (pointed to by the previous Symbolic Link) is created to host the content of a custom DLL that contains the code we want to inject.
3. A DLL imported by an executable running as a PPL is hijacked and our code is executed.

The most important thing to keep in mind here is that the whole exploit relies on a weakness that _exists_ in PPLs but not in PPs. Indeed, _PPLs can load DLLs from the `\KnownDlls` directory_, whereas PPs always load DLLs from the disk. This is a key difference because the digital signature of a DLL is only checked when it is initially read from the disk to create a new Section object. It is not checked afterward when it is mapped in the virtual address space of the Process.

## What is going on with build 19044.1826?

The debug output of PPLdump was already provided in the GitHub [issue](https://github.com/itm4n/PPLdump/issues/12) but I reproduced it in a Windows 10 VM with the July 2022 update pack (Windows 10 21H2 Build 19044.1826).

```console
C:\WINDOWS\system32>c:\Temp\PPLdump.exe -d lsass lsass.dmp
[lab-admin] [*] Found a process with name 'lsass' and PID 740
[DEBUG][lab-admin] Check requirements
[DEBUG][lab-admin] Target process protection level: 4 - PsProtectedSignerLsa-Light
[lab-admin] [*] Requirements OK
[...]
[DEBUG][lab-admin] Call DefineDosDevice to create '\KnownDlls\EventAggregation.dll' -> '\KernelObjects\EventAggregation.dll'
[lab-admin] [*] DefineDosDevice OK
[...]
[DEBUG][SYSTEM] Check whether the symbolic link was really created in '\KnownDlls\'
[SYSTEM] [+] The symbolic link was successfully created: '\KnownDlls\EventAggregation.dll' -> '\KernelObjects\EventAggregation.dll'
[...]
[DEBUG][SYSTEM] Create protected process with command line: C:\WINDOWS\system32\services.exe 740 "lsass.dmp" 2f2e0a5f-40d4-4034-ba27-81498c6869b -d
[SYSTEM] [*] Started protected process, waiting...
[DEBUG][SYSTEM] Unmap section '\KernelObjects\EventAggregation.dll'...
[DEBUG][SYSTEM] Process exit code: 0
[-] The DLL was not loaded. :/
```

Overall, the output looks pretty good, the symbolic link is properly created in `\KnownDlls` so, at first sight, the `DefineDosDevice` trick is still working fine. This can easily be confirmed with WinObj because the symbolic link cannot be deleted without the ability to execute code in a PPL at the "Windows TCB" level.

![WinObj - Symbolic link created in \KnownDlls](/assets/posts/2022-07-24-the-end-of-ppldump/01_winobj_knowndlls_symlink.png)

Then a new section is created with the content of our custom DLL but the tool ultimately fails with the error `[-] The DLL was not loaded.` after attempting to hijack `EventAggregation.dll`, which is normally loaded by `services.exe`.

In such a situation, the obvious thing to do is to fire up Process Monitor and see if we can spot anything that does not seem right.

![PPLdump debug with Process Monitor](/assets/posts/2022-07-24-the-end-of-ppldump/02_procmon_dll_loading.png)

From the very first events, we can already see that something is not going as planned. Since `services.exe` is executed as a PPL, we should not see any file operation (_e.g._ `CreateFile` or `CreateFileMapping`) on DLLs such as `kernel32.dll` and `KernelBase.dll` because these are __Known DLLs__. Instead, they should be loaded directly from their respective sections `\KnownDlls\kernel32.dll` and `\KnownDlls\kernelbase.dll`.

The conclusion is that PPLs now appear to be behaving just like PPs and therefore no longer rely on _Known DLLs_.

## A patch in NTDLL?

Something has evidently been changed in the way PPL processes are created. I already know where to look but for the sake of this post, I will do this the proper way through binary diffing.

I first got my hands on the last two versions of `ntdll.dll` for Windows 10 21H2 on [Winbindex](https://winbindex.m417z.com/?file=ntdll.dll) and I downloaded the public symbols using `symchk.exe` from the Windows SDK.

![NTDLL files to compare](/assets/posts/2022-07-24-the-end-of-ppldump/03_ntdll-files.png)

```console
C:\WINDOWS\System32>"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe" /s srv*C:\symbols*https://msdl.microsoft.com/download/symbols C:\Temp\ntdll_*.dll

SYMCHK: FAILED files = 0
SYMCHK: PASSED + IGNORED files = 2
```

After loading the files and analyzing them, I simply used the [BinDiff extension for Ghidra](https://github.com/google/binexport/releases) to export the result in the appropriate format.

![Ghidra - Files are exported](/assets/posts/2022-07-24-the-end-of-ppldump/04_ghidra-bindiff-export.png)

The two "BinExport" files can then be imported in BinDiff to compare the two versions of `ntdll.dll`. By sorting the functions by "similarity", we can immediately see that there are some slight differences in 7 functions but one really stands out: `LdrpInitializeProcess`. This is exactly the place where I expected to find some changes.

![BinDiff - The loader was modified](/assets/posts/2022-07-24-the-end-of-ppldump/05_bindiff-loader-diff.png)

We can also see that there is one unmatched function, which was added in the newest version: `Feature_Servicing_2206c_38427506__private_IsEnabled`.

![BinDiff - A function was added](/assets/posts/2022-07-24-the-end-of-ppldump/06_bindiff-new-function.png)

## Known DLL handling in the loader

Initially, when a new process is created, only NTDLL is loaded. The _image loader_ implemented in NTDLL is responsible for loading other DLLs (among a lot of other things). To determine whether it should use the _Known DLLs_ or not, it simply checks a couple of flags in the __Process Environment Block__ (`PEB`).

This check is highlighted in the following screenshot (build version `10.0.19044.1741`).

![Protection flag check](/assets/posts/2022-07-24-the-end-of-ppldump/07_ntdll-1741-peb-check.png)

The `PEB` structure is partially documented but we won't find the information we need in the official documentation. _Process Hacker_ on the other hand contains a way more detailed definition.

```cpp
// phnt/include/ntpebteb.h
typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace;      // Byte at (byte*)peb+0
    BOOLEAN ReadImageFileExecOptions;   // Byte at (byte*)peb+1
    BOOLEAN BeingDebugged;              // Byte at (byte*)peb+2
    union
    {
        BOOLEAN BitField;               // Byte at (byte*)peb+3
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        };
    };
    // ...
}
```

At the offset 3 (`peb + 3` in the `if` statement), we can find a byte value that holds a set of 8-bit flags. The least significant bit holds the value of the `ImageUsesLargePages` flag whilst the most significant bit holds the value of the `IsLongPathAwareProcess` flag.

![BitField](/assets/posts/2022-07-24-the-end-of-ppldump/08_peb-bitfield.svg)

With that knowledge, we can translate the code `*(byte *)(peb + 3)` to `peb->BitField`. Then, the value `0x42` is a mask that allows the loader to isolate and check the flags `IsProtectedProcess` and `IsProtectedProcessLight`. Therefore, the decompiled code `if ((*(byte *)(peb + 3) & 0x42) == 2)` can be interpreted as follows.

```cpp
if (peb->IsProtectedProcess && !peb->IsProtectedProcessLight) {
    // Do NOT use Known DLLs
} else {
    // Use Known DLLs
}
```

In other words, _Known DLLs_ are ignored __only if__ the process is a __PP__ and thus __PPLs__ behave just like normal processes. This is a confirmation of what we already know so let's find out what changed in the build version `10.0.19044.1806`.

If we search for the same line of code, we immediately realize that there is an additional check that depends on the value returned by `Feature_Servicing_2206c_38427506__private_IsEnabled()`. What a coincidence!

![Ghidra - A check was added to the loader](/assets/posts/2022-07-24-the-end-of-ppldump/09_ntdll-1806-peb-check.png)

In the `else` block, we can see the following check.

![Ghidra - The PEB check was modified](/assets/posts/2022-07-24-the-end-of-ppldump/10_ntdll-1806-new-peb-check.png)

The decompiled code generated by Ghidra can therefore be summarized as follows.

```cpp
bool bFeatureEnabled = Feature_Servicing_2206c_38427506__private_IsEnabled();
if (bFeatureEnabled == 0) {
    if ((*(byte *)(peb + 3) & 0x42) != 2) {
        // Use Known DLLs
    } else {
        // Do NOT use Known DLLs
    }
} else {
    if ((*(byte *)(peb + 3) & 2) != 0) {
        // Do NOT use Known DLLs
    } else {
        // Use Known DLLs
    }
}
```

If we apply the same logic I detailed earlier, we can translate the above code into this more readable version.

```cpp
bool bFeatureEnabled = Feature_Servicing_2206c_38427506__private_IsEnabled();
if (bFeatureEnabled == FALSE) {
    if (peb->IsProtectedProcess && !peb->IsProtectedProcessLight) {
        // Do NOT use Known DLLs
    } else {
        // Use Known DLLs
    }
} else {
    if (peb->IsProtectedProcess) {
        // Do NOT use Known DLLs
    } else {
        // Use Known DLLs
    }
}
```

The patch seems pretty clear now. First, there is a check on a "_feature servicing_" value. If this feature is disabled, the loader falls back to the previous version of the code and thus PPLs load _Known DLLs_. On the other hand, if this feature is enabled, the loader simply checks whether the flag `peb->IsProtectedProcess` is set or not. So, a _protected process_ (be it a PP or a PPL) will not use _Known DLLs_.

## A new check in the loader

In the previous part, we saw that the result of `Feature_Servicing_2206c_38427506__private_IsEnabled()` determines the logic that the loader will use regarding _Protected Processes_ and _Known DLLs_. At first glance, this function does not seem that complex so let's see what we can learn about it.

![Ghidra - The new Feature Servicing check](/assets/posts/2022-07-24-the-end-of-ppldump/11_ntdll-1806-servicing-feature-function-check.png)

According to the decompiled code generated by Ghidra, it seems that the function first retrieves the value of the global variable `Feature_Servicing_2206c_38427506__private_featureState`, initializes it if it was not already and returns the value of its fourth bit (`uVar1 >> 3 & 1`).

```cpp
DWORD Feature_Servicing_2206c_38427506__private_IsEnabled() {
    DWORD dwFeatureServicingState;
    BOOL bIsEnabled;
    
    dwFeatureServicingState = Feature_Servicing_2206c_38427506__private_featureState;
    if ((dwFeatureServicingState & 1) == 0) {
        // The global variable is not yet initialized, initialize it.
        dwFeatureServicingState = wil_details_FeatureStateCache_ReevaluateCachedFeatureEnabledState(...);
    }
    
    // Extract the fourth bit
    bIsEnabled = dwFeatureServicingState >> 3 & 1;

    // ...

    return bIsEnabled;
}
```

So, it looks like the global variable `Feature_Servicing_..._featureState` holds a set of bit flags that determine whether particular features are enabled or not. This is something we can quite easily verify with the help of a few lines of C/C++ and a debugger.

```cpp
#include <iostream>
#include <Windows.h>

typedef UINT(NTAPI* _FeatureIsEnabled)();

int wmain(int argc, wchar_t* argv[])
{
    DWORD dwOffsetFeatureIsEnabled      = 0x0009b360;
    DWORD dwOffsetFeatureServicingState = 0x0016d288;
    PDWORD pFeatureServicingState       = NULL;

    _FeatureIsEnabled FeatureIsEnabled  = NULL;
    BOOL bFeatureIsEnabled              = FALSE;

    // Get NTDLL base address
    HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
    // Calculate address of Feature_Servicing_..._featureState
    pFeatureServicingState = (PDWORD)((PBYTE)ntdll + dwOffsetFeatureServicingState);
    // Calculate address of Feature_Servicing_..._IsEnabled()
    FeatureIsEnabled = (_FeatureIsEnabled)((PBYTE)ntdll + dwOffsetFeatureIsEnabled);

    wprintf(L"Feature_Servicing_2206c_38427506__private_featureState: 0x%08x\r\n", *pFeatureServicingState);

    bFeatureIsEnabled = FeatureIsEnabled();
    wprintf(L"Feature enabled: %d\r\n", bFeatureIsEnabled);

    wprintf(L"----\r\n");

    wprintf(L"Setting the fourth bit to 0\r\n");
    *pFeatureServicingState = *pFeatureServicingState & 0xfffffff7;

    wprintf(L"Feature_Servicing_2206c_38427506__private_featureState: 0x%08x\r\n", *pFeatureServicingState);

    bFeatureIsEnabled = FeatureIsEnabled();
    wprintf(L"Feature enabled: %d\r\n", bFeatureIsEnabled);

    return 0;
}
```

Running the above code yields the following output.

```console
C:\WINDOWS\system32>C:\Temp\FeatureServicing.exe
Feature_Servicing_2206c_38427506__private_featureState: 0x0000001b
Feature enabled: 1
----
Setting the fourth bit to 0
Feature_Servicing_2206c_38427506__private_featureState: 0x00000013
Feature enabled: 0
```

The value of `Feature_Servicing_..._featureState` is `0x0000001b`, which translates to `0001 1011` in binary. As the fourth bit is set, the return value is `1`. In the second part, I manually unset the fourth bit using a bitwise AND operation with the mask `1111 0111` (_i.e._ `0xf7`). In this case, the return value is `0`, which tends to confirm my interpretation of the code.

Finally, and for good measure, we can also manually set the value of `Feature_Servicing_..._featureState` to `0` and check the value returned by `wil_..._ReevaluateCachedFeatureEnabledState(...)` to make sure it is `0x1b`.

![WinDbg - Cached value reevaluate](/assets/posts/2022-07-24-the-end-of-ppldump/12_windbg-feature-state-reevaluate.png)

The return value (see `RAX`) is `0x7ff700000000001b` but the `EAX` register (_i.e._ the first 32 bits of `RAX`) is used in the following operations (`mov ebx,eax`) so the effective value is indeed `0x0000001b`.

## Conclusion

I'm not sure what motivated Microsoft to differentiate PPs and PPLs regarding _Known DLLs_ in the first place. Perhaps it was a matter of performance, I don't know. Anyhow, they were already aware of this potential weakness, otherwise, they wouldn't have made an exception for PPs I guess. The thing is, this security hole is now patched and that's a good step forward. I like to think I played a little role in this change although I'm aware that all the work had already been done by Alex and James.

In conclusion, this is truly _The End of PPLdump_. However, this tool leveraged only one weakness of PPLs, but there is a couple of other _Userland_ issues we can probably still exploit. So, from my standpoint, it is also an opportunity to start working on another bypass...

## Links & Resources

- Windows Exploitation Tricks: Exploiting Arbitrary Object Directory Creation for Local Elevation of Privilege  
[https://googleprojectzero.blogspot.com/2018/08/windows-exploitation-tricks-exploiting.html](https://googleprojectzero.blogspot.com/2018/08/windows-exploitation-tricks-exploiting.html)
- Do You Really Know About LSA Protection (RunAsPPL)?  
[https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)
- Bypassing LSA Protection in Userland  
[https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/)