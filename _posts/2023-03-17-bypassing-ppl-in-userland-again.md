---
title: "Bypassing PPL in Userland (again)"
layout: "post"
categories: ["Windows"]
tags: ["Research", "Bypass", "Exploit"]
---

This post is a sequel to [Bypassing LSA Protection in Userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) and [The End of PPLdump](https://itm4n.github.io/the-end-of-ppldump/). Here, I will discuss how I was able to bypass the latest mitigation implemented by Microsoft and develop a new Userland exploit for injecting arbitrary code in a PPL with the highest signer type.


## The current state of PP(L)s

My previous work on protected processes (see [Bypassing LSA Protection in Userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/)) yielded a tool called [PPLdump](https://github.com/itm4n/PPLdump) showcasing the possibility for a user with administrator privileges to inject arbitrary code in such processes in Userland, thus effectively bypassing LSA protection without the need for a Kernel driver.

In July 2022 though, Microsoft put an end to this exploit _by preventing PPLs from loading "Known DLLs"_. To do so, they simply modified an `if` statement in the process initialization routine to make sure that the `\KnownDlls` directory handle is not initialized if the process is protected (_i.e._ PPL or PP), whereas previously this behavior was only effective for PPs. For more details, I would encourage you to read this blog post: [The End of PPLdump](https://itm4n.github.io/the-end-of-ppldump/).

However, the `\KnownDlls` directory handle initialization is only one part of the problem. The fundamental issue still remains, that is, a DLL's signature is not verified when it is mapped from a Section object. What this means for us is that, if we manage to write a valid object directory handle right where the `\KnownDlls` handle is normally initialized, we can still use the same kind of DLL hijacking exploit and thus inject unsigned code in a PPL.

There is nothing new here. This was already explained several years ago by Alex Ionescu and James Forshaw when they discussed the various techniques they found for injecting code in both PPLs and PPs. As such, the exploit chain I am going to discuss here mainly relies on things that were already described in the blog post series "_Injecting Code into Windows Protected Processes using COM_" ([Part 1](https://googleprojectzero.blogspot.com/2018/10/injecting-code-into-windows-protected.html), [Part 2](https://googleprojectzero.blogspot.com/2018/11/injecting-code-into-windows-protected.html)) by James Forshaw.

## The `\KnownDlls` handle

Our objective is to inject arbitrary code in a PPL at the highest protection level (_i.e._ `WinTcb`). To do so, we will adopt the following strategy:

1.  write a valid object directory handle (_e.g.:_ `\Foo`) right where the handle to `\KnownDlls` is normally initialized;
2.  create a Section object (_e.g.:_ `\Foo\Bar.dll`) from an arbitrary DLL in this object directory;
3.  coerce the target PPL to call `LoadLibrary(Ex)` (_e.g.:_ `LoadLibrary("Bar.dll")`) so that it loads our unsigned code.

What we need to achieve this scenario is a _write-what-where_ condition. The "_where_" part is trivial. The `\KnownDlls` handle is stored in the global variable `ntdll!LdrpKnownDllDirectoryHandle` and is therefore located at the same address for all processes.

If we attach to `explorer.exe` with WinDbg for instance, we can see that `ntdll!LdrpKnownDllDirectoryHandle` is located at `0x7ffafdc5c030` and has the value `0x3c`.

```console
0:066> dq ntdll!LdrpKnownDllDirectoryHandle L1
00007ffa`fdc5c030  00000000`0000003c
0:066> !handle 3C 5
Handle 3c
  Type             Directory
  Name             \KnownDlls
```

And if we attach to `spoolsv.exe` (Print Spooler service), we can see that `ntdll!LdrpKnownDllDirectoryHandle` indeed has the same address `0x7ffafdc5c030`, but a different value.

```console
0:009> dq ntdll!LdrpKnownDllDirectoryHandle L1
00007ffa`fdc5c030  00000000`00000044
0:009> !handle 44 5
Handle 44
  Type             Directory
  Name             \KnownDlls
```

As for the "_what_" part, it is a bit more complicated because the handle value we need to write must reference a **valid** Object Directory in the target PPL, and we cannot open the process with the access rights that would allow us to determine its value.

The solution to these two problems can be found with a tool such as System Informer, by inspecting the opened handles in a PPL _versus_ a normal process.

![Viewing Object Directory handles with System Informer](/assets/posts/2023-03-17-bypassing-ppl-in-userland-again/01_systeminformer-directory-handles.png)
_Viewing Object Directory handles with System Informer_

A "normal" process such as `explorer.exe` has at least two opened Directory handles (`\KnownDlls` and `\Sessions\1\BaseNamedObjects` in this example), whereas a PPL such as `wininit.exe` only has one. In the case of a PPL, System Informer does not show the Directory's name, because it would have to open the process with `PROCESS_DUP_HANDLE` in order to duplicate the handle and query its properties, which it cannot do precisely because the process is protected.

One way to work around this issue is to use a Kernel Debugger. Here, we can see that the handle references `\BaseNamedObjects`, which we could have guessed from our previous observation.

![Viewing information about a handle with WinDbg](/assets/posts/2023-03-17-bypassing-ppl-in-userland-again/02_windbg-wininit-directory-handle-name.png)
_Viewing information about a handle with WinDbg_

However, although System Informer did not show the Directory's name, it was still able to acquire a list of handles opened in the protected process. This is made possible by the `NtQuerySystemInformation` system call and the `SystemHandleInformation` information class. When calling this function, the system generously provides a list of all opened handles in all processes. Each handle entry is returned in the form of a `SYSTEM_HANDLE_TABLE_ENTRY_INFO` structure that contains 3 interesting members: `UniqueProcessId`, `ObjectTypeIndex` and `HandleValue`.

```cpp
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;
```

Thanks to the `UniqueProcessId` member, we will be able to list all the handles belonging to the PPL we target. The `ObjectTypeIndex` member will allow us to find only handles associated with an object of type "Directory". This way, we can determine the value of the handle to `\BaseNamedObjects` in virtually any protected process.

We now have both the "_what_" and "_where_" of our hypothetical _write-what-where_ condition. We still have to find the "_write_".

## COM type confusion

We need to find an arbitrary memory write primitive. However, relying on a 0-day vulnerability in a service or any other executable that can run as a PPL is not an option. What we can do though, is induce a type confusion in a protected process that exposes a COM object such as described in [Injecting Code into Windows Protected Processes using COM - Part 1](https://googleprojectzero.blogspot.com/2018/10/injecting-code-into-windows-protected.html).

Although (D)COM is built on top of DCE/RPC, there are fundamental differences between the two. With DCE/RPC, the process of _marshaling_ and _unmarshaling_ data is always static in the sense that it is predetermined at build time according to an IDL file. For example, the IDL of the [`MS-EFSR`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/4a25b8e1-fd90-41b6-9301-62ed71334436) interface describes how to marshal the data sent in a call to the procedure `EfsRpcOpenFileRaw` as follows.

```cpp
long EfsRpcOpenFileRaw(
    [in]            handle_t                   binding_h,
    [out]           PEXIMPORT_CONTEXT_HANDLE * hContext,
    [in, string]    wchar_t                  * FileName,
    [in]            long                       Flags
);
```

With (D)COM, however, this process may rely on a **Type Library**, in which case _marshaling_ is determined at **runtime**. Let us consider the following dummy example. We have a Type Library that describes the interface `ICounter`. This interface has one method, `GetCounterValue`, which takes a `CounterName` as an input value, and returns a `CounterValue`.

```cpp
interface ICounter : IUnknown {
    HRESULT GetCounterValue([in] BSTR Name, [out] ULONG* Value);
};
```

In this configuration, the `out` parameter `Value` is not _marshaled_ by the client. It will be marshaled by the server when the server-side `GetCounterValue` routine returns.

![Diagram illustrating the dynamic generation of a Proxy and Stub from a Type Library](/assets/posts/2023-03-17-bypassing-ppl-in-userland-again/03_diagram_legit_typelib.png)
_Diagram illustrating the dynamic generation of a Proxy and Stub from a Type Library_

However, if we somehow manage to force the server to load a Type Library we control, we could change the interface definition like this, and thus induce a type confusion.

```cpp
interface ICounter : IUnknown {
    HRESULT GetCounterValue([in] BSTR Name, [in] ULONG Value);
};
```

In this new configuration, the parameter `Value` becomes an attacker-controlled input that will be marshaled as is when calling the server's Stub. However, on server side, the `GetCounterValue` routine will still treat it as a pointer, resulting in a **type confusion**. In this example, a zero would be written at an arbitrary address.

![Diagram illustrating a type confusion caused by a hijacked Type Library](/assets/posts/2023-03-17-bypassing-ppl-in-userland-again/04_diagram_malicious_typelib.png)
_Diagram illustrating a type confusion caused by a hijacked Type Library_

If we can find a protected process that exposes such a COM object, we could use this trick to achieve our _write-what-where_ condition.

## Windows Update Medic Service (WaaSMedicSvc)

Before working on this project, I had already worked on the Windows Update Medic Service, so I knew it was an interesting target for that purpose.

This service runs inside a PPL with the Signer type `Windows`. This is not the maximum value (`WinTcb`), but we will get to that a bit later.

![Viewing the properties of `WaaSMedicSvc` with System Informer](/assets/posts/2023-03-17-bypassing-ppl-in-userland-again/05_system-informer-waasmedicsvc.png)
_Viewing the properties of `WaaSMedicSvc` with System Informer_

This service exposes two COM objects: `WaaSProtectedSettingsProvider` and `WaaSRemediation`. The latter implements several interfaces, one of which is `IWaaSRemediationEx`, which has an associated Type Library.

![Listing the COM objects exposed by `WaaSMedicSvc`](/assets/posts/2023-03-17-bypassing-ppl-in-userland-again/06_oleviewdotnet-waasremediation.png)
_Listing the COM objects exposed by `WaaSMedicSvc`_

If we create an instance of `WaaSRemediation` from OleViewDotNet, we can indeed see a call to `LoadRegTypeLib` with Process Monitor, resulting in the file `C:\Windows\System32\WaaSMedicPS.dll` being _loaded_.

![Observing a Proxy/Stub DLL being loaded by `WaaSMedicSvc` with Process Monitor](/assets/posts/2023-03-17-bypassing-ppl-in-userland-again/07_procmon-load-typelib.png)
_Observing a Proxy/Stub DLL being loaded by `WaaSMedicSvc` with Process Monitor_

The class `WaaSRemediation` has the CLSID `72566E27-1ABB-4EB3-B4F0-EB431CB1CB32`, so we can find its registration information at the following location in the registry: `HKLM\SOFTWARE\Classes\CLSID\{72566e27-1abb-4eb3-b4f0-eb431cb1cb32}`.

![Viewing the properties of the class `WaaSRemediation` in the Registry](/assets/posts/2023-03-17-bypassing-ppl-in-userland-again/08_registry-waasremediation.png)
_Viewing the properties of the class `WaaSRemediation` in the Registry_

The Type Library has the ID `3ff1aab8-f3d8-11d4-825d-00104b3646c0`, so we can find it at the following location: `HKLM\SOFTWARE\Classes\TypeLib\{3ff1aab8-f3d8-11d4-825d-00104b3646c0}`. The TypeLib path is stored in the key `1.0\0\Win64`.

![Viewing the properties of the Type Library `WaaSRemediationLib` in the Registry](/assets/posts/2023-03-17-bypassing-ppl-in-userland-again/09_registry-typelib.png)
_Viewing the properties of the Type Library `WaaSRemediationLib` in the Registry_

The target file is a DLL, so we should not be able to hijack it since the process is protected, right? Well, it turns out Type Libraries can be either stored as _standalone_ `.tlb` files or embedded in an EXE/DLL. Even in the latter case, this is not a problem, as explained by J.F.:

> _[…] a type library is just data so can be loaded into a PPL without any signing level violations._

If we want to hijack this Type Library, we just have to edit the registry key `...\1.0\0\Win64` and set the path of a Type Library file under our control before creating an instance of the `WaaSRemediation` class.

## The `IWaaSRemediationEx` interface

Now that we know how we can hijack the Type Library, we should focus on the interface(s) and method(s) we can override. To do so, we can first inspect the content of the original TypeLib with OleViewDotNet or OleView (which comes with the Windows SDK).

```cpp
interface IWaaSRemediationEx : IDispatch {
    [id(0x60020000)]
    HRESULT LaunchDetectionOnly(
                    [in] BSTR bstrCallerApplicationName, 
                    [out, retval] BSTR* pbstrPlugins);
    [id(0x60020001)]
    HRESULT LaunchRemediationOnly(
                    [in] BSTR bstrPlugins, 
                    [in] BSTR bstrCallerApplicationName, 
                    [out, retval] VARIANT* varResults);
};
```

The interface has two procedures, `LaunchDetectionOnly` and `LaunchRemediationOnly`. Each of them has an `out` return value we can override so that the server writes _arbitrary_ data at an address under our control.

With a bit of static reverse engineering, we can see that, ultimately, they both call the internal function `LaunchRemediationHelper`.

```cpp
// LaunchDetectionOnly
hr = LaunchRemediationHelper(..., NULL, param_1, &pwszResult);
if (FAILED(hr)) {
    // Report failure
}
*param_2 = SysAllocString(pwszResult);
```

In the following corresponding assembly, we control `RSI`. So, this is rather straightforward, we could have the value returned by `SysAllocString` being written at an arbitrary location.

```nasm
CALL  qword ptr [->OLEAUT32.DLL::SysAllocString]
MOV   qword ptr [RSI],RAX
```

The value returned by `LaunchRemediationOnly` is a `VARIANT`. The type of the `VARIANT` is `VT_UINT` (_i.e._ `0x17`) and its value is the result of `LaunchRemediationHelper`.

```cpp
// LaunchRemediationOnly
hr = LaunchRemediationHelper(..., param_1, param_2, NULL);
if (FAILED(hr)) {
    // Report failure
}
param_3->vt = VT_UINT; // 0x17 (23)
param_3->uintVal = hr;
```

In the following corresponding assembly, we control `RDI`. So, we could have the `WORD` `0x17` being written at an arbitrary location and the result of `LaunchRemediationHelper` being written 8 bytes after this address. In addition, as far as I can say, `LaunchRemediationHelper` always returns `S_OK` (_i.e._ `0x00000000`).

```nasm
MOV   EAX,0x17
MOV   word ptr [RDI],AX
MOV   dword ptr [RDI + 0x8],EBX
```

Therefore, our potential _write_ primitive could be summarized as follows, where `xx` represents an unknown value being written, and `??` represents a value in memory that would be left unmodified.

```plaintext
IWaaSRemediationEx::LaunchDetectionOnly
    -> xx xx xx xx xx xx xx xx
IWaaSRemediationEx::LaunchRemediationOnly
    -> 17 00 ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ??
```

These two primitives are not great, to say the least, but is there any way we could leverage them for achieving our goal?

## An arbitrary write primitive?

Our objective is to write the handle value of the object directory `\BaseNamedObjects` at the address of `ntdll!LdrpKnownDllDirectoryHandle`. There are some characteristics about handles that are worth mentioning here.

-   Handles are defined as pointers (`typedef void *HANDLE`) so they are stored as **8-byte values** on 64-bits systems.
-   Handles are **not random**, they are created incrementally starting from `0x04` with increments of 4.
-   The **lower 2 bits** of a handle value are **ignored** (see this brief post by Raymond Chen from 2005: [Why are kernel HANDLEs always a multiple of four?](https://devblogs.microsoft.com/oldnewthing/20050121-00/?p=36633)).

In our case, the `\BaseNamedObjects` handle is opened in the early stages of the process creation, so its value should not exceed `0xfc` and should therefore fit in a single byte. In addition, if the handle value is `0x54` for instance, the three next values `0x55`, `0x56` and `0x57`, are also perfectly valid.

In the previous part, we saw that we can force `LaunchDetectionOnly` to write a heap address returned by `SysAllocString` at an arbitrary address. Such an address could be `0x1fade7354b8` for instance, or `b8 54 73 de fa 01 00 00`, following the little-endian representation.

If we consider this address as a simple series of bytes, we can see that it contains the value we want - `0x54` - assuming the value of the `\BaseNamedObjects` handle is `0x54`. Thanks to our type confusion trick, we can force the service to write the returned heap address at `ntdll!LdrpKnownDllDirectoryHandle-1`, which would yield something like this in memory.

![Memory layout after a call to `LaunchDetectionOnly`](/assets/posts/2023-03-17-bypassing-ppl-in-userland-again/10_memory-layout-1.png)
_Memory layout after a call to `LaunchDetectionOnly`_

Of course, we want the value `54 00 00 00 00 00 00 00`, not `54 73 de fa 01 00 00 00` so we need to set the 4 extra bytes to zero. This is where `LaunchRemediationOnly` comes in handy. We know that this method can be used to write the pattern `17 00 ?? ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ??`, which conveniently contains 4 consecutive zeroes. Writing this pattern at `ntdll!LdrpKnownDllDirectoryHandle-7` will yield something like this in memory.

![Memory layout after a call to `LaunchRemediationOnly`](/assets/posts/2023-03-17-bypassing-ppl-in-userland-again/11_memory-layout-2.png)
_Memory layout after a call to `LaunchRemediationOnly`_

And we finally get the expected handle value! Of course, this is a trivial example as the address returned by `LaunchDetectionOnly` contained the byte we needed. In an actual exploit, we would have no way to know the value of the address returned by `SysAllocString`. We would not know at which offset from `ntdll!LdrpKnownDllDirectoryHandle` we should write either.

That being said, although heap addresses are random, they follow some alignment rules we might be able to exploit. So, I compiled a dataset of 2000 addresses returned by `LaunchDetectionOnly` and I used a simple Excel spreadsheet to determine the best strategy to adopt depending on the handle value we want to write. Remember that this value is something we can determine even though the target process is protected.

I will spare you the boring details, but essentially, the most efficient strategy would be:

1.  If the target handle value is `0x18` plus a multiple of 32 (_e.g._ `0x38`, `0x58`, etc.), write the address exactly at `ntdll!LdrpKnownDllDirectoryHandle` and invoke `LaunchRemediationOnly` twice to clear the five remaining _random_ bytes.
2.  Otherwise, write the address at `ntdll!LdrpKnownDllDirectoryHandle-1` and invoke `LaunchRemediationOnly` once to clear the four remaining _random_ bytes.

Then, it is theoretically just a matter of repeating this until we hit the appropriate value.

## Testing the memory write

Now that we have an exploit strategy, we should implement it and test it. The first step is to create the Type Library. As explained earlier, I simply transformed the two `out` parameters into `[in] ULONGLONG` input values.

```cpp
interface IWaaSRemediationEx : IDispatch {
    [id(0x60020000)]
    HRESULT LaunchDetectionOnly(
                    [in] BSTR bstrCallerApplicationName, 
                    [in] ULONGLONG pbstrPlugins);
    [id(0x60020001)]
    HRESULT LaunchRemediationOnly(
                    [in] BSTR bstrPlugins, 
                    [in] BSTR bstrCallerApplicationName, 
                    [in] ULONGLONG varResults);
};
```

Then, we can use the following code to check whether everything is working as expected. Please note that, for testing purposes, the address of `ntdll!LdrpKnownDllDirectoryHandle` is simply hardcoded here.

```cpp
DWORD64 dwKnownDllDirectoryHandle;
DWORD64 dwLaunchRemediationOnly;
DWORD64 dwLaunchDetectionOnly;
BSTR ClientApplication = SysAllocString(L"");
BSTR Plugins = SysAllocString(L"");
IWaaSRemediationEx* pWaaSRemediationEx;

// Where to write?
dwKnownDllDirectoryHandle = 0x00007fff971dc030;
dwLaunchDetectionOnly = dwKnownDllDirectoryHandle - 1;
dwLaunchRemediationOnly = dwKnownDllDirectoryHandle - 7;

// Create an instance of the object WaaSRemediation
CoCreateInstance(
    CLSID_WaaSRemediation,
    NULL,
    CLSCTX_LOCAL_SERVER,
    IID_PPV_ARGS(&pWaaSRemediationEx)
);

// Write the address returned by SysAllocString at dwLaunchDetectionOnly
pWaaSRemediationEx->LaunchDetectionOnly(
    ClientApplication, 
    dwLaunchDetectionOnly
);

// Write result at dwLaunchRemediationOnly to clear unwanted bytes
pWaaSRemediationEx->LaunchRemediationOnly(
    Plugins,
    ClientApplication,
    dwLaunchRemediationOnly
);

pWaaSRemediationEx->Release();
```

Unfortunately, this is not that simple. The initial call to `LaunchDetectionOnly` works fine, but then, any subsequent call to either of the two methods results in a crash, as shown in the below WinDbg output.

```console
(2a28.2c3c): Invalid handle - code c0000008 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
ntdll!KiRaiseUserExceptionDispatcher+0x3a:
00007fff`7199108a 8b8424c0000000  mov     eax,dword ptr [rsp+0C0h] ss:00000055`2db7bf70=c0000008
0:002> k
 # Child-SP          RetAddr           Call Site
00 00000055`2db7beb0 00007fff`71905157 ntdll!KiRaiseUserExceptionDispatcher+0x3a
01 00000055`2db7bf80 00007fff`719043ea ntdll!LdrpFindKnownDll+0x77
02 00000055`2db7bff0 00007fff`719088a8 ntdll!LdrpLoadKnownDll+0x52
03 00000055`2db7c050 00007fff`71907b29 ntdll!LdrpLoadDependentModule+0xcc8
04 00000055`2db7c5b0 00007fff`71904c14 ntdll!LdrpMapAndSnapDependency+0x199
05 00000055`2db7c630 00007fff`7194fdd3 ntdll!LdrpMapDllWithSectionHandle+0x184
06 00000055`2db7c680 00007fff`7194fb00 ntdll!LdrpMapDllNtFileName+0x19f
07 00000055`2db7c780 00007fff`7194ed9f ntdll!LdrpMapDllFullPath+0xe0
08 00000055`2db7c910 00007fff`7190fb53 ntdll!LdrpProcessWork+0x123
09 00000055`2db7c970 00007fff`719073e4 ntdll!LdrpLoadDllInternal+0x13f
0a 00000055`2db7c9f0 00007fff`71906af4 ntdll!LdrpLoadDll+0xa8
0b 00000055`2db7cba0 00007fff`6f11ae52 ntdll!LdrLoadDll+0xe4
0c 00000055`2db7cc90 00007fff`5cf1ab37 KERNELBASE!LoadLibraryExW+0x162
0d 00000055`2db7cd00 00007fff`5cf19903 waasmedicsvc!WaasMedic::CWaasRemediation::LoadPluginLibrary+0x15f
0e 00000055`2db7cf80 00007fff`5cf3656e waasmedicsvc!WaasMedic::CWaasRemediation::RunEx+0x223
0f 00000055`2db7d170 00007fff`5cf361d2 waasmedicsvc!WaaSRemediationAgent::LaunchRemediationHelper+0x1ce
10 00000055`2db7d2b0 00007fff`7128fd0f waasmedicsvc!WaaSRemediationAgent::LaunchDetectionOnly+0xf2
[...]
```

The function `LdrpFindKnownDll`, which originates from `LoadLibraryExW`, raises the exception `0xC0000008`, _i.e._ `EXCEPTION_INVALID_HANDLE`. At this point in the execution, the value of the `\KnownDlls` directory handle is indeed something like `0x00000001c026de8b`, and `LoadLibraryExW` does not like it. Who would have thought?…

To figure out why `LoadLibraryExW` is called, we need to better understand how `LaunchDetectionOnly` and `LaunchRemediationOnly` work. First of all, as we saw earlier, these two methods call the same helper function - `LaunchRemediationHelper` - but with slightly different input parameters. The `LaunchRemediationHelper` method itself creates an instance of the `CWaasRemediation` class and uses it to invoke the method `RunEx`. Only then, things start getting more interesting as `RunEx` calls the evocative method `LoadPluginLibrary`.

```cpp
DWORD WaasMedic::CWaasRemediation::LoadPluginLibrary(
    CWaasRemediation *this, LPWSTR pwszFilePath) {

    WCHAR pwszPluginDllPath[MAX_PATH+1];
    HANDLE hFile;
    BOOL bTestSigning;
    HMODULE hLibrary;

    ExpandEnvironmentStringsW(pwszFilePath, pwszPluginDllPath, MAX_PATH);
    
    hFile = CreateFileW(pwszPluginDllPath, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (IsTrustedLibrary(pwszPluginDllPath)) {
        if (IsTestSigningEnabled()) {
            hLibrary = LoadLibraryExW(
                pwszPluginDllPath, NULL,
                LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_REQUIRE_SIGNED_TARGET
            );
        } else {
            hLibrary = LoadLibraryW(pwszPluginDllPath);
        }
    }
}
```

This method is where the call to the `LoadLibraryExW` API originates from. Prior to that call, we can see that the target file is opened with `CreateFileW`, and then, the path is passed to the internal function `IsTrustedLibrary`. If we can cause one of these two functions to fail, we can prevent the plugin DLL from being loaded and thus prevent the crash.

One could think that we can preemptively open the target file without sharing any access rights, but as James Forshaw outlined in this [bug report](https://bugs.chromium.org/p/project-zero/issues/detail?id=1112), this is not that simple.

> _[…] if you don’t have the possibility of write permission on the file the OS automatically applies FILE_SHARE_READ which makes it impossible to lock the file in its entirety […]_

However, he also describes the following alternative approach.

> _We can cause the read to fail by using the `LockFile` API to put an exclusive lock on that part of the file._

The internal function `IsTrustedLibrary` ultimately calls the (undocumented) `WTGetSignatureInfo` API. This API needs to read the target file to verify its signature. We can use this behavior to our advantage and lock a portion of the file to cause this operation to fail.

On top of that, this has a very nice side effect for our exploit. With this simple trick, we can cause both `LaunchDetectionOnly` and `LaunchRemediationOnly` to fail in a controlled way, without altering their return values. Concretely, this means that, instead of taking a few seconds to execute, the calls will return almost instantly, thus rendering the overall exploitation much faster.

## "Known" DLL hijacking

In the previous parts, we saw how we could obtain a primitive that allows us to write a **random** byte at the address of `ntdll!LdrpKnownDllDirectoryHandle`. Unfortunately, we have no way of figuring out what value is written. The only thing we can do is just try to hijack a DLL and see if it is loaded thanks to a synchronization object such as an `Event` for instance. If not, we just have to repeat until we succeed.

The question is, how can we force the service to load a DLL? There are multiple solutions to this problem, but the one I opted for is rather opportunistic. We saw a bit earlier that the `WaaSRemediation` class also implements the `ITaskHandler` interface. The Proxy and Stub for this interface are implemented in `TaskSchedPS.dll`. Therefore, the first time it is used, the COM runtime will attempt to load this DLL.

![Observing the DLL `TaskSchd.dll` being loaded by `WaaSMedicSvc` with Process Monitor](/assets/posts/2023-03-17-bypassing-ppl-in-userland-again/12_procmon_loadlibrary-taskschdps.png)
_Observing the DLL `TaskSchd.dll` being loaded by `WaaSMedicSvc` with Process Monitor_

Hijacking such a DLL also has an added benefit. Proxy/Stub DLLs must implement 4 standard functions: `DllGetClassObject`, `DllCanUnloadNow`, `DllRegisterServer` and `DllUnregisterServer`. The function `DllGetClassObject`, in particular, is called when instantiating an object, so we can use it to implement our payload, and thus avoid the hassle of having to deal with the loader's lock in `DllMain`.

![Viewing the export table of TaskSchd.dll with PE Bear](/assets/posts/2023-03-17-bypassing-ppl-in-userland-again/13_pebear-taskschdps-exports.png)
_Viewing the export table of TaskSchd.dll with PE Bear_

"_In theory, there is no difference between theory and practice. But, in practice, there is._" This is all too true. When implementing this, I faced three worth-mentioning issues.

The first one is a quirk I did not take the time to fully investigate. If the name of the loaded DLL is `foo.dll`, the loader tries to open the file `\foo.dll` after mapping the section in the process' address space. This results in a failed file access to `C:\foo.dll`, causing the loader to return the status code `0xc0000034` (`STATUS_OBJECT_NAME_NOT_FOUND`). As a simple workaround for my exploit, I chose to create the file `C:\foo.dll` and delete it once I am done. It is not elegant but it works.

The second issue I encountered is that the target process randomly crashes when trying to load the DLL. This seems to occur when the written handle value is `0x01`, `0x02`, or `0x03`. In this case, although these values are not null, they all represent a null handle. Unfortunately, I have not been able to reproduce this issue reliably. In any case, if this occurs in the remote process, we must cancel our call to `CoCreateInstance`, otherwise, it will hang indefinitely.

Last but not least, the third issue was that my DLL failed to load with the error `STATUS_INVALID_IMAGE_HASH`. The plain English message corresponding to this error is "_Windows cannot verify the digital signature for this file_". Guess what, this is exactly the error you would get when attempting to load an unsigned DLL in a protected process.

## The devil is in the details

The last issue I mentioned drove me crazy for a while. At some point, I really thought I was back to square one. In the end, it turned out my testing methodology was flawed, which caused me to overlook one very important detail.

During the exploit development phase, I was carefully debugging everything with WinDbg. To do this in Userland, I disabled the protection of the target process using [PPLKiller](https://github.com/RedCursorSecurityConsulting/PPLKiller). In this configuration, everything worked and my DLL was loaded. It is only when I tested it in real conditions that I realized that it was actually loaded from the local file instead of the Section.

Using Process Monitor, we can see the following call stack leading to the call to the `LoadLibraryEx` API.

![Viewing the call stack leading to `LoadLibraryExW` with Process Monitor](/assets/posts/2023-03-17-bypassing-ppl-in-userland-again/14_procmon-loaddll-loadlibrary.png)
_Viewing the call stack leading to `LoadLibraryExW` with Process Monitor_


Essentially, the method `LoadDll` retrieves some flags to pass to `LoadLibraryEx` and then calls `LoadLibraryWithLogging`.

```cpp
// CClassCache::CDllPathEntry::LoadDll()
dwFlags = GetLoadLibraryAlteredSearchPathFlag();
LoadLibraryWithLogging(LVar7, pwszDllPath, dwFlags, param_5);

// LoadLibraryWithLogging()
hModule = LoadLibraryExW(pwszDllPath, NULL, dwFlags);

The flags passed to LoadLibraryEx are very important as they can highly impact the way DLLs are loaded, so we have to understand how they are determined in GetLoadLibraryAlteredSearchPathFlag.

ulong GetLoadLibraryAlteredSearchPathFlag(void) {
    AppModelPolicy_PolicyValue* polDllSearchOrder;
    
    if (g_LoadLibraryAlteredSearchPathFlag == 0xffffffff) {
    
        AppModelPolicy_GetPolicy_Internal(
          AppModelPolicy_Type_DllSearchOrder,
          polDllSearchOrder);

        if (*polDllSearchOrder == AppModelPolicy_DllSearchOrder_Traditional) {
            g_LoadLibraryAlteredSearchPathFlag = 0x2008;
        } else {
            // ...
        }
    }
    return g_LoadLibraryAlteredSearchPathFlag;
}
```

The function `GetLoadLibraryAlteredSearchPathFlag` is relatively simple. It first checks whether the global variable `g_LoadLibraryAlteredSearchPathFlag` is initialized. If not, it calls an internal method that retrieves a value corresponding to the policy currently enforced on the machine, sets `g_LoadLibraryAlteredSearchPathFlag` accordingly, and finally returns its value.

Checking this global variable in the target process with WinDbg reveals the following value.

```console
0:004> x combase!g_LoadLibraryAlteredSearchPathFlag
00007ff9`137225a4 combase!g_LoadLibraryAlteredSearchPathFlag = 0x2008
```

The value `0x2008` is a combination of the flags `LOAD_LIBRARY_SAFE_CURRENT_DIRS` (`0x2000`) and `LOAD_WITH_ALTERED_SEARCH_PATH` (`0x0008`). The flag `LOAD_LIBRARY_SAFE_CURRENT_DIRS` only affects DLLs being loaded from the current directory, so it should not be a problem in our case.

![Description of the flag `LOAD_LIBRARY_SAFE_CURRENT_DIRS`](/assets/posts/2023-03-17-bypassing-ppl-in-userland-again/15_doc-safe-current-dirs.png)
_Description of the flag `LOAD_LIBRARY_SAFE_CURRENT_DIRS`_

As for the flag `LOAD_WITH_ALTERED_SEARCH_PATH`, it is a different story. The documentation states that, if this flag is used and the input path is relative, the behavior of `LoadLibraryEx`

![Description of the flag `LOAD_WITH_ALTERED_SEARCH_PATH`](/assets/posts/2023-03-17-bypassing-ppl-in-userland-again/16_doc-altered-search-path.png)
_Description of the flag `LOAD_WITH_ALTERED_SEARCH_PATH`_

This is unfortunate, but there is a simple solution to this problem. You probably noticed that the flags are stored in a global variable. As such, they are located in the R/W `.data` section of `combase.dll`. Therefore, we can use our memory write primitive right before the exploit loop to set this value to zero (_i.e._ no flags). Without any flags specified, the call to `LoadLibraryEx` would basically be equivalent to a simple call to `LoadLibrary`.

## Beyond PPL-Windows

At this point, we have successfully injected unsigned code in a PPL with the signer type `Windows`. It is more than enough for accessing a protected LSASS process or a protected AV/EDR, but it would be nice if we could reach the highest level `WinTcb`.

![Diagram showing the Signer type hierarchy](/assets/posts/2023-03-17-bypassing-ppl-in-userland-again/17_diagram-signer-types.png)
_Diagram showing the Signer type hierarchy_

It turns out a PPL at any signing level can elevate to `WinTcb`. This is nothing new though, it was also already explained by James Forshaw in the part "Elevating to PPL-Windows TCB" of the post [Injecting Code into Windows Protected Processes using COM - Part 1](https://googleprojectzero.blogspot.com/2018/10/injecting-code-into-windows-protected.html).

There is a sort of _backdoor_ that allows PPLs to create a fake cached signature for an arbitrary DLL. To learn more about this technique, I would encourage you to read the previously mentioned post and the bug report for CVE-2017-11830 [CiSetFileCache TOCTOU Security Feature Bypass](https://bugs.chromium.org/p/project-zero/issues/detail?id=1332).

Once we have generated a faked cached signature for our DLL, we can start `WerFaultSecure.exe` as a PPL with the signer type `WinTcb` and thus inject arbitrary code into it.

## Closing words

All in all, the exploit chain described in this blog post is way more complex than the one used in [PPLdump](https://github.com/itm4n/PPLdump). I did my best to implement all the techniques and tricks described here in the most reliable way, but ultimately, there is a random factor that is impossible to fully manage. If you are interested to test it, I released a new tool on GitHub: [PPLmedic](https://github.com/itm4n/PPLmedic).

![Screenshot showing the execution of the Proof-of-Concept on Windows 10](/assets/posts/2023-03-17-bypassing-ppl-in-userland-again/18_poc-win10.png)
_Screenshot showing the execution of the Proof-of-Concept on Windows 10_

This Proof-of-Concept offers only a memory dump functionality, just like [PPLdump](https://github.com/itm4n/PPLdump), but there is a lot more you can do once you have the ability to execute arbitrary code in a PPL with the signer type `WinTcb` and `SYSTEM` privileges. As demonstrated by [SecIdiot](https://github.com/SecIdiot) (the account seems to have been deleted), in their Proof-of-Concept [ANGRYORCHARD](https://web.archive.org/web/20221001053039/https://github.com/SecIdiot/ANGRYORCHARD) (link to archive.org), you can inject code in CSRSS, and then exploit a known Kernel R/W primitive through a syscall that is only available to this process.

Finally, what about mitigations and detection, you might ask? Regarding mitigations, Microsoft made it clear that protected processes are not a security boundary, so they should not be taken too seriously. It does not mean they are completely useless though. Enabling LSA protection, for instance, will force an attacker attempting to dump LSASS to use either a Kernel driver or a complex Userland exploit such as the one described here, thus increasing the chance of detection by the Blue team. Speaking of detection, the same rules that already applied to credential extraction attempts still apply here. As for the detection of the tool itself, I am sure Microsoft will rapidly come up with a signature, as they did for PPLdump.

## Links & Resources

- James Forshaw - Injecting Code into Windows Protected Processes using COM - Part 1  
[https://googleprojectzero.blogspot.com/2018/10/injecting-code-into-windows-protected.html](https://googleprojectzero.blogspot.com/2018/10/injecting-code-into-windows-protected.html)
- James Forshaw - Injecting Code into Windows Protected Processes using COM - Part 2  
[https://googleprojectzero.blogspot.com/2018/11/injecting-code-into-windows-protected.html](https://googleprojectzero.blogspot.com/2018/11/injecting-code-into-windows-protected.html)
- Raymond Chen - Why are kernel HANDLEs always a multiple of four?  
[https://devblogs.microsoft.com/oldnewthing/20050121-00/?p=36633](https://devblogs.microsoft.com/oldnewthing/20050121-00/?p=36633)
- Acebond - GitHub/PPLKiller  
[https://github.com/RedCursorSecurityConsulting/PPLKiller](https://github.com/RedCursorSecurityConsulting/PPLKiller)
- James Forshaw - CiSetFileCache TOCTOU Security Feature Bypass  
[https://bugs.chromium.org/p/project-zero/issues/detail?id=1332](https://bugs.chromium.org/p/project-zero/issues/detail?id=1332)

**_This article was originally posted on SCRT’s blog [here](https://blog.scrt.ch/2023/03/17/bypassing-ppl-in-userland-again/)._**