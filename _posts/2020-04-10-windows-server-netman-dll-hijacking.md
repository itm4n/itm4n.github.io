---
title: "Windows Server 2008R2-2019 NetMan DLL Hijacking" 
layout: "post"
categories: [ "Privilege Escalation" ]
tags: [ "Research", "Privilege Escalation", "Exploit" ]
---

What if I told you that __all editions of Windows Server__, __from 2008R2 to 2019__, are prone to __a DLL Hijacking in the `%PATH%` directories__? What if I also told you that the impacted service runs as `NT AUTHORITY\SYSTEM` and that the DLL loading __can be triggered by a normal user__, __on demand__, and without the need of a machine reboot? Provided that you found some `%PATH%` directories configured with weak permissions, this would probably be the most straightforward privilege escalation technique I know. I don't know why there hasn't been any publication about this yet. Anyway, I'll try to fill this gap.


## Foreword

To start things off, I probably don't need to clarify this but __DLL hijacking is not considered as a vulnerability__ by Microsoft ([source](https://msrc-blog.microsoft.com/2018/04/04/triaging-a-dll-planting-vulnerability/)). I tend to agree with this statement because, by default, even if a DLL is loaded from the `%PATH%` directories by a process running with higher privileges, __this behavior cannot be exploited by a normal user__. Though in practice, and especially in corporate environments, it's quite common to see third-party applications configured with weak folder permissions. In addition, if they add themselves to the system's `%PATH%`, the entire system is then put at risk. My personal opinion on the subject is that Microsoft should prevent these _uncontrolled_ DLL loadings as far as possible in order to prevent __a minor configuration issue__ affecting a single application from becoming __a privilege escalation attack vector__ with a way higher impact. 

## Back to Basics: Searching for DLL Hijacking Using Procmon

This discovery is the unexpected result of some research I was doing on __Windows 2008 R2__. Although the system is no longer supported, it's still widespread in corporate networks and, I was looking for the easiest way of exploiting binary planting through my [CVE-2020-0668](https://itm4n.github.io/cve-2020-0668-windows-service-tracing-eop/) exploit. I've done a lot of research on Windows 10 Worsktation during the past few months and working back on Windows 7/2008 R2 required me to forget about some techniques I've learned and to restart from the beginning. My original problem was: how to _easily_ exploit arbitrary files writes on Windows 2008 R2?

My first instinct was to start with the __IKEEXT__ service. On a default installation of Windows 2008 R2, this service is stopped, and it tries to load the missing `wlbsctrl.dll` library whenever it's started. A normal user can __easily trigger this service__ simply by attempting to __initiate a dummy VPN connection__. However, starting it only once affects its start mode, it goes from `DEMAND_START` to `AUTOMATIC`. Leveraging this service under such circumstances would therefore require a machine reboot, which makes it a far less interesting target. So, I had to look for other ways. I also considered the different __DLL hijacking__ opportunities documented by __Frédéric Bourla__ in his article entitled "[A few binary plating 0-days for Windows](https://www.reddit.com/r/hacking/comments/b0lr05/a_few_binary_plating_0days_for_windows/)" but they are either not easy to trigger or _appear_ quite randomly.

I decided to begin my research process with firing up Process Monitor and checking for __DLL loading events failing with a__ `NAME NOT FOUND` __error__. In the context of an arbitrary file write exploit, the research doesn't have to be limited to the `%PATH%` folders so this yields a lot of results! To refine the research, I therefore added a constraint. I wanted to filter out processes which try to load a DLL from the `C:\Windows\System32\` folder and then find it in another Windows folder, especially if they need it to function properly. The objective is to avoid a Denial of Service as far as possible. 

I considered 3 DLL hijacking cases:

- A program loads __a DLL which doesn't exist__ in `C:\Windows\System32\` __but exists in another Windows directory__, `C:\Windows\System\` for example. Since the `C:\Windows\System32\` folder has a higher priority, this could be a valid candidate.
- A program loads __a non-existing DLL__ but uses a __safe DLL search order__. Therefore, it only tries to load it from the `C:\Windows\System32\` folder for example.
- A program loads __a non-existing DLL__ and uses an __unrestricted DLL search order__.

The first case might lead to Denial of Service so I left it aside. The second case is interesting but can be a bit difficult to spot amongst all the results returned by Procmon. The third case is definetly the most interesting one. If the DLL doesn't exist, the risk of causing a Denial of Service when hijacking it is reduced and it's also easy to spot in Procmon. 

To do so, I didn't add a new filter in Process Monitor. Instead, I simply added __a rule which highlights all the paths containing__ `WindowsPowerShell`. Why this particular keyword, you may ask. On all (modern) versions of Windows, `C:\Windows\System32\WindowsPowerShell\v1.0\` is part of the default `%PATH%` folders. Therefore, whenever you see a program trying to load a DLL from this folder, it most probably means that it is prone to __DLL Hijacking__. 

I then tried to start/stop each __service__ or __scheduled task__ I could. And, after having spent a few hours staring at Procmon's output, I finally saw this:

![](/assets/posts/2020-04-10-windows-server-netman-dll-hijacking/01_procmon-dll-hijacking-search-wlanhlp.png)

Wait, what?! Is this really what I think it is? :astonished: Is this a non-existing DLL being loaded by a service running as `NT AUTHORITY\SYSTEM`? My first thought was: "if `wlanhlp.dll` is a _hijackable_ DLL, I should already know about it, I must have made a mistake somewhere or I must have installed some third-party app causing this". But then I remembered. Firstly, I'm using a fresh install of Windows Server 2008 R2 in a dedicated VM. The only third party application is "VMware Tools". Secondly, all the research I've done so far was mostly on Worstation editions of Windows because it's often more convenient. Could it be the reason why I saw this event only now?

Fortunately, I have another VM with Windows 7 installed so I quickly checked. It turns out that this DLL exists on a Workstation edition! 

![](/assets/posts/2020-04-10-windows-server-netman-dll-hijacking/02_windows7-wlanhlp-file.png)

If you think about it, if `wlanhlp.dll` is really related to Wlan capabilities as its name implies, it would make sense. The Wlan API is only available on Workstation editions by default and must be installed as an additional component on Server editions. Anyway, I must be on to something...

## NetMan and the Missing Wlan API

Let's start by looking at the properties of the event in Procmon and learn more about the service. 

![](/assets/posts/2020-04-10-windows-server-netman-dll-hijacking/03_procmon-properties-process.png)

The process runs as `NT AUTHORITY\SYSTEM`, that's some good news for us. It has the PID 972 so let's check the corresponding service in the Task Manager. 

![](/assets/posts/2020-04-10-windows-server-netman-dll-hijacking/04_taskmgr-pid-search.png)

Three services run inside this process. Looking at the Stack Trace of the event in Procmon, we should be able to determine the name of the one which tried to load this DLL.

![](/assets/posts/2020-04-10-windows-server-netman-dll-hijacking/05_procmon-2008r2-stack-trace.png)

We can see an occurrence of `netman.dll` so the corresponding service must be __NetMan__ (a.k.a. _Network Connections_). That's one problem solved. If we take a closer look at this Stack Trace, we also notice several lines containing references to `RPCRT4.dll` or `ole32.dll`. That's a good sign. It means that __this event was most probably triggered through RPC/COM__. If so, there is a chance we can also trigger this event as a normal user with a few lines of code but I'm getting ahead of myself.

This DLL hijacking opportunity is due to the fact that the Wlan API is not installed by default on a server edition of Windows 6.1 (7 / 2008 R2). The question is: does the same principle apply to other versions of Windows? :thinking:

Luckily, I use quite a lot of virtual machines for my research and I had instances of Windows Server 2012 R2 and 2019 already set up so it didn't take long to verify. 

On Windows Server 2012 R2, `wlanhlp.dll` doesn't show up in Procmon. However `wlanapi.dll` does instead. Looking at the details of the event, it turns out that it is identical. This means that Windows 6.3 (8.1 / 2012 R2) is also "affected". 

![](/assets/posts/2020-04-10-windows-server-netman-dll-hijacking/06_procmon-2012r2-wlanapi.png)

Ok, this version of Windows is pretty old now, Windows 2019 cannot be affected by the same issue, right? Let's check this out...

![](/assets/posts/2020-04-10-windows-server-netman-dll-hijacking/07_procmon-windows2019-wlanapi.png)

The exact same behavior occurs on Windows Server 2019 as well! :smirk: I ended up checking this on all possible versions of Windows Server from 2008 to 2019. I won't bore you with the details, __all the versions are prone to this DLL hijacking__. The only one which I couldn't test thoroughly was Server 2008, I wasn't able to reproduce the issue on this one.

## How to Trigger this DLL Hijacking Event on Demand?

Let's summarize the situation. On all versions of Windows Server, the __NetMan__ service, which runs as `NT AUTHORITY\SYSTEM`, tries to load the __missing__ `wlanhlp.dll` __or__ `wlanapi.dll` __DLL__ without using a safe DLL search order. Therefore it ends up __trying to load this DLL from the directories which are listed in the system's__ `%PATH%` __environement variable__. That's a great start I'd say! :slightly_smiling_face:

The next step is to figure out if we can trigger this event as a normal user. I already mentionned that this behavior was due to some RPC/COM events but it doesn't necessarily mean that we can trigger it. This event could also be the result of two services communicating with each other through RPC.

Anyway, let's hope for the best and start by checking the Stack Trace once again but, this time, using an instance of Procmon configured to use the public symbols provided by Microsoft. To do so, I switched to the Windows 10 VM I use for security research.

![](/assets/posts/2020-04-10-windows-server-netman-dll-hijacking/08_procmon-stack-trace-symbols.png)

We can see that the `CLanConnection::GetProperties()` method is called here. In other events, the `CLanConnection::GetPropertiesEx()` method is called instead. Let's see if we can find these methods by inspecting the COM objects exposed by __NetMan__ using [OleViewDotNet](https://github.com/tyranid/oleviewdotnet).

![](/assets/posts/2020-04-10-windows-server-netman-dll-hijacking/09_oleviewdotnet-netman-classes.png)

Simply based on the name of the class, the `LAN Connection Class` seems like a good candidate. So, I created an instance of this class and checked the details of the `INetConnection` interface. 

![](/assets/posts/2020-04-10-windows-server-netman-dll-hijacking/10_oleviewdotnet-inetconnection.png)

Here it is! We can see the `CLanConnection::GetProperties()` method. We're getting close! :ok_hand:

At this point, I was thinking that all of this looked too good to be true. First, I saw this __DLL hijacking__ which I had never seen before. Then, I saw that it was __triggered by an RPC/COM event__. Finally, __finding it with OleViewDotNet was trivial__. There had to be a catch! Though, only one problem could arise now: restrictive permissions on the COM object. 

COM objects are securable too and they have ACLs which define who is allowed to use them. So, we need to check this before going any further. 

![](/assets/posts/2020-04-10-windows-server-netman-dll-hijacking/11_oleviewdotnet-object-permissions.png)

When I first saw `Administrators` and `NT AUTHORITY\...`, I thought for a second, "crap, this can only be triggered by high-privileged accounts". And then I saw `NT AUTHORITY\INTERACTIVE`, phew... :sweat_smile:

What this actually means is that this COM object can be used by normal users __only if__ they are authenticated using an __interactive session__. More specifically, you'd need to logon locally on the server. Not very useful, right?! Well, it turns out that when you connect through RDP (this includes VDI), you get an interactive session as well so, under these circumstances, this COM object could be used by a normal user. Otherwise, if you tried to use it in a WinRM session for example, you'd get an "Access denied" error. That's not as good as I expected initially but that's still a seemingly interesting trigger.

The below screenshot shows a command prompt opened in an RDP session on Windows Server 2019.

![](/assets/posts/2020-04-10-windows-server-netman-dll-hijacking/12_rdp-user-groups.png)

At this point, the research part is over so let's write some code! Fortunately, the `INetConnection` interface is documented ([here](https://docs.microsoft.com/en-us/windows/win32/api/netcon/nn-netcon-inetconnection)). This makes things a lot easier. Secondly, while searching how to enumerate the network interfaces with `INetConnection->EnumConnections()`, I stumbled upon an interesting solution posted by [Simon Mourier](https://stackoverflow.com/users/403671/simon-mourier) on StackOverflow [here](https://stackoverflow.com/questions/5917304/how-do-i-detect-a-disabled-network-interface-connection-from-a-windows-applicati/5942359#5942359). Yes, I copied some code from StackOverflow, that's a bit lame, I know... :neutral_face:

Here is _my_ final Proof-of-Concept code:

```cpp
// https://stackoverflow.com/questions/5917304/how-do-i-detect-a-disabled-network-interface-connection-from-a-windows-applicati/5942359#5942359

#include <iostream>
#include <comdef.h>
#include <netcon.h>

int main()
{
    HRESULT hResult;

    typedef void(__stdcall* LPNcFreeNetconProperties)(NETCON_PROPERTIES* pProps);
    HMODULE hModule = LoadLibrary(L"netshell.dll");
    if (hModule == NULL) { return 1; }
    LPNcFreeNetconProperties NcFreeNetconProperties = (LPNcFreeNetconProperties)GetProcAddress(hModule, "NcFreeNetconProperties");

    hResult = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (SUCCEEDED(hResult))
    {
        INetConnectionManager* pConnectionManager = 0;
        hResult = CoCreateInstance(CLSID_ConnectionManager, 0, CLSCTX_ALL, __uuidof(INetConnectionManager), (void**)&pConnectionManager);
        if (SUCCEEDED(hResult))
        {
            IEnumNetConnection* pEnumConnection = 0;
            hResult = pConnectionManager->EnumConnections(NCME_DEFAULT, &pEnumConnection);
            if (SUCCEEDED(hResult))
            {
                INetConnection* pConnection = 0;
                ULONG count;
                while (pEnumConnection->Next(1, &pConnection, &count) == S_OK)
                {
                    NETCON_PROPERTIES* pConnectionProperties = 0;
                    hResult = pConnection->GetProperties(&pConnectionProperties);
                    if (SUCCEEDED(hResult))
                    {
                        wprintf(L"Interface: %ls\n", pConnectionProperties->pszwName);
                        NcFreeNetconProperties(pConnectionProperties);
                    }
                    else
                        wprintf(L"[-] INetConnection::GetProperties() failed. Error code = 0x%08X (%ls)\n", hResult, _com_error(hResult).ErrorMessage());
                    pConnection->Release();
                }
                pEnumConnection->Release();
            }
            else
                wprintf(L"[-] IEnumNetConnection::EnumConnections() failed. Error code = 0x%08X (%ls)\n", hResult, _com_error(hResult).ErrorMessage());
            pConnectionManager->Release();
        }
        else
            wprintf(L"[-] CoCreateInstance() failed. Error code = 0x%08X (%ls)\n", hResult, _com_error(hResult).ErrorMessage());
        CoUninitialize();
    }
    else
        wprintf(L"[-] CoInitializeEx() failed. Error code = 0x%08X (%ls)\n", hResult, _com_error(hResult).ErrorMessage());
    
    FreeLibrary(hModule);
    wprintf(L"Done\n");
}
```

The below screenshot shows the final result on Windows Server 2008 R2. As we can see, we can trigger the DLL loading simply by enumerating the Ethernet interfaces of the machine. No need to say that the machine must have at least one Ethernet interface, otherwise this technique doesn't work. :smile:

![](/assets/posts/2020-04-10-windows-server-netman-dll-hijacking/13_windows-2008r2-trigger.png)

The screenshot below shows an attempt to run the same executable as a normal user connected through a remote PowerShell session on Windows Server 2019.

![](/assets/posts/2020-04-10-windows-server-netman-dll-hijacking/14_winrm.png)

## (2020-04-13 update) Dealing with the INTERACTIVE restriction

A couple days after the publication of this blog post, [@splinter_code](https://twitter.com/splinter_code) brought to my attention that it was technically possible to __spawn an interactive process from a non-interactive one__.

Then, I had the chance to exchange a few words with him. It turns out that he developped a tool called [RunasCs](https://github.com/antonioCoco/RunasCs) which implements among other things __a generic way for spawning an interactive process__. He also took the time to explain to me how it works. This trick involves some Windows internals subtleties which are not commonly well known. I won't detail the technique here because it would require a dedicated blog post in order to explain everything clearly but I'll try to give a high-level explanation. I hope we will see a blog post from the author himself soon! :slightly_smiling_face:

To put it simple, you can call `CreateProcessWithLogon()` in order to create __an interactive process__. This function requires the name and the password of the target user. The problem is that if you try to do that from a process running in session 0 (where most of the services live), the child process will immediately die. A typical example is when you connect remotely through WinRM. All your commands are executed through a subprocess running in session 0 with your identity.

Why is it a problem? You may ask. The thing is, an __interactive__ process is called this way because it interacts with a desktop, which is a particular securable object in the Windows world. However, in the case of our WinRM process which runs in session 0, you wouldn't (and you shouldn't) be allowed to interact with this desktop. What [@splinter_code](https://twitter.com/splinter_code) found is that you can edit the ACL of the desktop object in the context of the current process in order to grant the current user access to this object. Child processes will then inherit these permissions and therefore have a desktop to interact with. Really clever!

As you can see on the below screenshot, using this trick, we can spawn __an interactive process__ and therefore run `NetManTrigger.exe` as if we were logged in locally. :slightly_smiling_face:

![](/assets/posts/2020-04-10-windows-server-netman-dll-hijacking/15_winrm-interactive-process.png)

## Conclusion

Following this analysis, I can say that the __NetMan__ service is probably the __most useful target for DLL Hijacking__ I know about. ~~It comes with a small caveat though. __As a normal user__ you would need an __interactive session__ (RDP / VDI), which makes it quite useless if you're logged on through a remote PowerShell session for instance.~~ But there is another interesting case, if you've compromised another service running as `LOCAL SERVICE` or `NETWORK SERVICE`, then you would still be able to trigger the __NetMan__ service to elevate your privileges to `SYSTEM`.

With this discovery, I also learned a lesson. Focusing your attention and your research on a particular environment may sometimes prevent you from finding interesting stuff, which turns out to be particularly relevant in the context of a pentest. 

Last but not least, I integrated this in my __Windows Privilege Escalation Check__ script - [PrivescCheck](https://github.com/itm4n/PrivescCheck). Depending on the version of Windows, the `Invoke-HijackableDllsCheck` function will tell you which DLL may potentially be hijacked through the `%PATH%` directories. Thanks [@1mm0rt41](https://twitter.com/1mm0rt411) for suggesting the idea! :thumbsup:

## Links & Resources

- Microsoft Security Response Center (MSRC) - Triaging a DLL planting vulnerability  
[https://msrc-blog.microsoft.com/2018/04/04/triaging-a-dll-planting-vulnerability/](https://msrc-blog.microsoft.com/2018/04/04/triaging-a-dll-planting-vulnerability/)
- CVE-2020-0668 - A Trivial Privilege Escalation Bug in Windows Service Tracing  
[https://itm4n.github.io/cve-2020-0668-windows-service-tracing-eop/](https://itm4n.github.io/cve-2020-0668-windows-service-tracing-eop/)
- A few binary planting 0-days for Windows  
[https://www.reddit.com/r/hacking/comments/b0lr05/a_few_binary_plating_0days_for_windows/](https://www.reddit.com/r/hacking/comments/b0lr05/a_few_binary_plating_0days_for_windows/)
- RunasCs - How to spawn an interactive process  
[https://github.com/antonioCoco/RunasCs](https://github.com/antonioCoco/RunasCs)
