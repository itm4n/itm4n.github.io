---
title: "Weaponizing Privileged File Writes with the USO Service - Part 2/2"
layout: "post"
categories: "Windows"
tags: ["Research", "Privilege Escalation", "Exploit"]
---

In the previous post, I showed how the __USO client__ could be used to interact with the __USO service__ and thus have it load the `windowscoredeviceinfo.dll` DLL on demand with the `StartScan` option. I wasn't totally satisfied with this though. So, I reverse engineered a part of the client and the server in order to __replicate its behavior as a standalone project__ that could be reused in future exploits. This is what I'll try to show and explain in this second part.  


## USO client - Static analysis 

Although I also used Ghidra during my research process, I'll stick to IDA in this demonstration for consistency and because of its debugging capabilities. 

Before opening `usoclient.exe` in IDA, I downloaded the corresponding PDB file with the following command. Theoritically, IDA will do this automatically but I found that it doesn't always work. The PDB file can then be loaded with `File > Load File > PDB File...`. 

`symchk` comes with Windows SDK and is generally located in `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\`.

```batch
symchk /s "srv*c:\symbols*https://msdl.microsoft.com/download/symbols" "c:\windows\system32\usoclient.exe"
```

__Note:__ _PDB stands for "Program Database". Program database (PDB) is a proprietary file format (developed by Microsoft) for storing debugging information about a program (or, commonly, program modules such as a DLL or EXE)._ Source: [Wikipedia](https://en.wikipedia.org/wiki/Program_database)

`usoclient.exe` is now opened in IDA and the symbols are loaded, where do we go from here? Well, here the starting point is quite obvious. We know that the `StartScan` option is a valid "trigger" so, we will naturally look for occurrences of this string in the binary and enumerate all the `Xrefs` to find out where it's used. 

![](/assets/posts/2019-08-19-usodllloader-part2/21_IDA-StartScan-XrefsTo.png)

The `StartScan` string is used inside two functions: `PerformOperationOnSession()` and `PerformOperationOnManager()`. Let's check the first one and generate the corresponding pseudocode. 

![](/assets/posts/2019-08-19-usodllloader-part2/22_IDA-PerformOperationOnSession.png)

This seems to be a "_Switch Case Statement_". The input is compared against a list of hardcoded commands: `StartScan`, `StartDownload`, `StartInstall`, etc. If there is a match, an action is taken. 

For example, when the `StartScan` option is used, the following code is run. 

```c
v5 = *(_QWORD *)(*(_QWORD *)v3 + 168i64);
v6 = _guard_dispatch_icall_fptr(v3, 0i64);
if ( v6 >= 0 )
  return 0i64;
```

This code doesn't make much sense. :thinking: So, I considered it as a dead end for the moment and decided to go up instead by looking for `Xrefs` to this function. 

![](/assets/posts/2019-08-19-usodllloader-part2/23_PerformOperationOnSession-Xrefs.png)

This function is called only once so it's pretty straightforward. 

![](/assets/posts/2019-08-19-usodllloader-part2/24_IDA-USOclient-CoSetProxyBlanket.png)

I then had a quick look at the pseudocode and I immediately spotted the following calls: `CoInitializeEx()`, `CoCreateInstance()`, `CoSetProxyBlanket()`, etc. Because I already played around with COM (Component Object Model) before, I recognized the sequence of API calls.

Let's take a closer look at the following call.

![](/assets/posts/2019-08-19-usodllloader-part2/25_IDA-USOclient-CoCreateInstance.png)

According to Microsoft documentation, you can call `CoCreateInstance()` to _create a single uninitialized object of the class associated with a specified CLSID_ (Source: [CoCreateInstance function](https://docs.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance))

Here is the prototype of the function: 

```cpp
HRESULT CoCreateInstance(
  REFCLSID  rclsid,
  LPUNKNOWN pUnkOuter,
  DWORD     dwClsContext,
  REFIID    riid,
  LPVOID    *ppv
);
```

- `rclsid` is _the CLSID associated with the data and code that will be used to create the object_.
- `riid` is _a reference to the identifier of the interface to be used to communicate with the object_.

If we apply this to the call in the USO client, it means that the object with the CLSID `b91d5831-b1bd-4608-8198-d72e155020f7` will be created and the interface with the IID `07f3afac-7c8a-4ce7-a5e0-3d24ee8a77e0` will be used to communicate with it. 

Having read the article [Exploiting Arbitrary File Writes for Local Elevation of Privilege](https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html) by [James Forshaw](https://twitter.com/tiraniddo) several times, I knew what I had to do next. Thanks to his tool called `OleViewDotNet`, it should be quite easy to __reverse engineer the DCOM object__.

If you're already familiar with this concept, you can skip the next part. For more information: [https://docs.microsoft.com/en-us/windows/win32/com/inter-object-communication](https://docs.microsoft.com/en-us/windows/win32/com/inter-object-communication).


## A quick word about (D)COM 

As I said earlier, COM stands for _Component Object Model_. It's a standard defined by Microsoft for inter process communications. Since I don't know much about this technology myself, I won't go into the details. 

The key point to keep in mind though is how the __communication between a client and a server__ is done. It is described on the following diagram. The client's call goes through a ___Proxy___ and then through a _Channel_ which is part of the _COM library_. The marshaled call is transmitted to the server's process thanks to the _RPC runtime_ and finally, the parameters are unmarshaled by the ___Stub___ before being forwarded to the server. 

![](/assets/posts/2019-08-19-usodllloader-part2/dcom-marshaling.png)

The obvious consequence is that we will find only the proxy definition on client side and, we might miss some key information from the server's side. 


## Reverse engineering a COM communication (almost) by hand 

Let's start the reverse engineering of the COM object. __We already know its CLSID__ so, using `OleViewDotNet`, this step should be straigthforward, right? 

First we can __enumerate all the objects__ exposed by the services running on the host by going to `Registry > Local Services`. Since we also know the name of the service, we can narrow down the list with the keywork `orchestrator`. __This yields a few objects__ that we can inspect manually to find the one we are looking for: `UpdateSessionOrchestrator`. The __CLSID__ matches the one we saw earlier while reverse engineering the USO client: `b91d5831-b1bd-4608-8198-d72e155020f7`.

The next step would be to expand the corresponding node in order to enumerate all the interfaces of the object. However, in this case it failed with the following error: `Error querying COM interface - ClassFactory cannot supply requested class`. 

![](/assets/posts/2019-08-19-usodllloader-part2/26_OleViewDotNet-Orchestrator-Failed.png)

OK, never mind, we will have to do it manually. From this point on, I went for a dynamic analysis of the client in order to see how the RPC calls worked. 

To do so, I used those three tools:
- __IDA__ (with debug symbols configured)
- __IDA__'s x86_64 Windows debug server - `C:\Program Files (x86)\IDA 6.8\dbgsrv\win64_remotex64.exe`
- __WinDbg__ (with debug symbols configured)

We already know that the `CoCreateInstance()` call is used to instantiate the remote COM object. As a result the variable `pInterface`, as its name implies, holds a pointer to the interface with the IID `07f3afac-7c8a-4ce7-a5e0-3d24ee8a77e0`, which will be used to communicate with the object. My goal now is to understand what happens next. Therefore, I put a breakpoint on the first `_guard_dispatch_icall_fptr` call that comes right after. 

![](/assets/posts/2019-08-19-usodllloader-part2/27_IDA-call-sequence.png)

Here is what happens right before the call:
1. The `RCX` register holds the location of the interface's pointer (i.e. `pInterface`). 
2. The value pointed to by `RCX` is loaded into `RAX` - i.e. `RAX` = `pInterface`. 
3. The value that was stored in `RSI` is copied to `RDX`- We don't know what it is yet.
4. The value pointed to by `RAX+0x28` is loaded into `RAX` - i.e. `ProxyVTable[5]` as we will see.

![](/assets/posts/2019-08-19-usodllloader-part2/28_IDA-break-1.png)
![](/assets/posts/2019-08-19-usodllloader-part2/29_IDA-break-1-registers.png)

The value of `RCX` is `0x000002344FA53D68`. Let's see what we can find at this address with WinDbg.

```plaintext
0:000> dqs 0x00002344FA53D68 L1
00000234`4fa53d68  00007ff8`e48fd560 usoapi!IUpdateSessionOrchestratorProxyVtbl+0x10
```

We find the start address of the Proxy VTable of the UpdateSessionOrchestrator's interface. We can then enumerate all the pointers listed in the VTable. 

```plaintext
0:000> dqs 0x00007ff8e48fd560 LB
00007ff8`e48fd560  00007ff8`e48f8040 usoapi!IUnknown_QueryInterface_Proxy
00007ff8`e48fd568  00007ff8`e48f7d90 usoapi!IUnknown_AddRef_Proxy
00007ff8`e48fd570  00007ff8`e48f7ed0 usoapi!IUnknown_Release_Proxy
00007ff8`e48fd578  00007ff8`e48f7dc0 usoapi!ObjectStublessClient3
00007ff8`e48fd580  00007ff8`e48f8090 usoapi!ObjectStublessClient4
00007ff8`e48fd588  00007ff8`e48f7e80 usoapi!ObjectStublessClient5
00007ff8`e48fd590  00007ff8`e48f7ef0 usoapi!ObjectStublessClient6
00007ff8`e48fd598  00007ff8`e48f7e60 usoapi!ObjectStublessClient7
00007ff8`e48fd5a0  00007ff8`e49068b0 usoapi!IID_IMoUsoUpdate
00007ff8`e48fd5a8  00007ff8`e48fefb0 usoapi!CAutomaticUpdates::`vftable'+0x3b0
00007ff8`e48fd5b0  00000000`00000019
```

The first three functions are `QueryInterface`, `AddRef` and `Release`. These are the functions that a COM interface inherits from `IUnknown`. Then, there are 5 other functions but we don't know their names.

In order to find more information about the VTable, we have to inspect the server. We know the name of the COM object - `UpdateSessionOrchestrator` - and we know the name of the service - `USOsvc`. So, theoritically, we should find all the information we need in `usosvc.dll`.

```plaintext
.rdata:00000001800582F8 dq offset UpdateSessionOrchestrator::QueryInterface(void)
.rdata:0000000180058300 dq offset UpdateSessionOrchestrator::AddRef(void)
.rdata:0000000180058308 dq offset UpdateSessionOrchestrator::Release(void)
.rdata:0000000180058310 dq offset UpdateSessionOrchestrator::CreateUpdateSession(tagUpdateSessionType,_GUID const &,void * *)
.rdata:0000000180058318 dq offset UpdateSessionOrchestrator::GetCurrentActiveUpdateSessions(IUsoSessionCollection * *)
.rdata:0000000180058320 dq offset UpdateSessionOrchestrator::LogTaskRunning(ushort const *)
.rdata:0000000180058328 dq offset UpdateSessionOrchestrator::CreateUxUpdateManager(IUxUpdateManager * *)
.rdata:0000000180058330 dq offset UpdateSessionOrchestrator::CreateUniversalOrchestrator(IUniversalOrchestrator * *)
```

Nice! :relaxed: Here is the complete VTable. We can see that the function at offset 5 is `UpdateSessionOrchestrator::LogTaskRunning(ushort const *)`.

Finally, the value of RDX is `0x000002344FA39450`. Let's check what we can find at this address as well, with IDA this time:

![](/assets/posts/2019-08-19-usodllloader-part2/31_IDA-break-1-startscan-str.png)

It's just a pointer to the null terminated unicode string `L"StartScan"`. 

All this information can be summarized as follows.
```plaintext
RAX = VTable[5] = `UpdateSessionOrchestrator::LogTaskRunning(ushort const *)`
RCX = argv[0]   = `UpdateSessionOrchestrator pInterface`
RDX = argv[1]   = L"StartScan"
```

If we consider the x86_64 calling convention of Windows, this can be represented by the following pseudocode.
```cpp
pInterface->LogTaskRunning(L"StartScan");
```

The same process can be applied to the next call.

![](/assets/posts/2019-08-19-usodllloader-part2/32_IDA-break-2.png)

This would yield the following:
```plaintext
RAX = VTable[0] = `UpdateSessionOrchestrator::QueryInterface()`
RCX = argv[0]   = `UpdateSessionOrchestrator pInterface`
RDX = argv[1]   = `*GUID(c57692f8-8f5f-47cb-9381-34329b40285a)`
R8  = argv[2]   = Output pointer location 
```

Here, the returned value is `NULL` so, all the code after the `if` statement would be ignored. 

![](/assets/posts/2019-08-19-usodllloader-part2/33_IDA-break-2-check.png)

Therefore, we can skip it and jump right here:

![](/assets/posts/2019-08-19-usodllloader-part2/34_IDA-break-3.png)

Nice! :sunglasses: Were are getting closer to the target `PerformOperationOnSession()` call. 

With the same reverse engineering process, we find the following.
```plaintext
RAX = VTable[3] = `UpdateSessionOrchestrator::CreateUpdateSession(tagUpdateSessionType,_GUID const &,void * *)`
RCX = argv[0]   = `UpdateSessionOrchestrator pInterface`
RDX = argv[1]   = 1
R8  = argv[2]   = `*GUID(fccc288d-b47e-41fa-970c-935ec952f4a4)`
R9  = argv[3]   = `void **param_3 (usoapi!IUsoSessionCommonProxyVtbl+0x10)` --> IUsoSessionCommon pProxy 
```

Here, we can see that another interface is involded: `IUsoSessionCommon`. It's identified by the IID `fccc288d-b47e-41fa-970c-935ec952f4a4` and its VTable has 68 entries so I won't list all the functions here. 

Next there is a `CoSetProxyBlanket()` call. This is a standard WinApi function that is used to _set the authentication information that will be used to make calls on the specified proxy_ (Source: [CoSetProxyBlanket function](https://docs.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cosetproxyblanket)).

![](/assets/posts/2019-08-19-usodllloader-part2/35_IDA-CoSetProxyBlanket.png)

If we translate all the hexadecimal values back to Win32 constants, this yields the following API call. 

```cpp
IUsoSessionCommonPtr usoSessionCommon;
CoSetProxyBlanket(usoSessionCommon, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, NULL);
```

Now, we can enter the `PerformOperationOnSession()` function and, we are back to the piece of code that didn't make sense before. However, thanks to the reverse engineering process we just went through, this is now getting clearer. This is a simple call on the `IUsoSessionCommon` proxy. We just need to determine __which function__ is called and with __which parameters__. 

![](/assets/posts/2019-08-19-usodllloader-part2/36_IDA-break-4.png)

![](/assets/posts/2019-08-19-usodllloader-part2/37_IDA-break-4-instructions.png)

With this final breakpoint, the function's offset and the parameters can be easily determined.
```plaintext
RAX = VTable[21] = combase_NdrProxyForwardingFunction21
RCX = argv[0]    = IUsoSessionCommon pProxy
RDX = argv[1]    = 0
R8  = argv[2]    = 0
R9  = argv[3]    = L"ScanTriggerUsoClient"
```

This would be equivalent to the following pseudocode.
```cpp
pProxy->Proc21(0, 0, L"ScanTriggerUsoClient");
```

If all the pieces are put together, the "StartScan" action in the USO client can be summarized with the following simplified code. 
```cpp
HRESULT hResult;
// Initialize the COM library
hResult = CoInitializeEx(0, COINIT_MULTITHREADED);
// Create the remote UpdateSessionOrchestrator object
GUID CLSID_UpdateSessionOrchestrator = { 0xb91d5831, 0xb1bd, 0x4608, { 0x81, 0x98, 0xd7, 0x2e, 0x15, 0x50, 0x20, 0xf7 } };
IUpdateSessionOrchestratorPtr updateSessionOrchestrator;
hResult = CoCreateInstance(CLSID_UpdateSessionOrchestrator, nullptr, CLSCTX_LOCAL_SERVER, IID_PPV_ARGS(&updateSessionOrchestrator));
// Invoke LogTaskRunning() 
updateSessionOrchestrator->LogTaskRunning(L"StartScan");
// Create an update session 
IUsoSessionCommonPtr usoSessionCommon;
GUID IID_IUsoSessionCommon = { 0xfccc288d, 0xb47e, 0x41fa, { 0x97, 0x0c, 0x93, 0x5e, 0xc9, 0x52, 0xf4, 0xa4 } };
updateSessionOrchestrator->CreateUpdateSession(1, &IID_IUsoSessionCommon, &usoSessionCommon);
// Set the authentication information 
CoSetProxyBlanket(usoSessionCommon, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, NULL);
// Trigger the "StartScan" action
usoSessionCommon->Proc21(0, 0, L"ScanTriggerUsoClient")
// Close the COM library  
CoUninitialize();
```

## Conclusion 

Knowing how the USO client works and how it can trigger privileged actions, it is now possible to replicate this behavior as a standalone application: [UsoDllLoader](https://github.com/itm4n/UsoDllLoader). Of course, the transition from this reverse engineering process to the actual C++ code requires a bit more work but it's not the most interesting part so I skipped it. The only thing that I should mention though is that the DiagHub PoC did help a lot. 

Regarding the reverse engineering part, I have to say that it wasn't too difficult because the COM client already exists and is provided with Windows by default. OleViewDotNet did help a lot in the end as well. It was able to generate the code for the second interface (UsoSessionCommon) - you know, the one with 68 functions! :relieved: 

Well, that wraps it up for this post. I hope you enjoyed it. :relaxed: 


## Links & Resources 

- Microsoft Documentation - CoCreateInstance  
[https://docs.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance](https://docs.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance)  
- Microsoft Documentation - Inter-Object Communications  
[https://docs.microsoft.com/en-us/windows/win32/com/inter-object-communication](https://docs.microsoft.com/en-us/windows/win32/com/inter-object-communication)  
- Microosft Documentation - x64 calling convention  
[https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention?view=vs-2019](https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention?view=vs-2019)  
- Windows Exploitation Tricks: Exploiting Arbitrary File Writes for Local Elevation of Privilege  
[https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html](https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html)