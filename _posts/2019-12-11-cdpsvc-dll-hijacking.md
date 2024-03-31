---
title: "CDPSvc DLL Hijacking - From LOCAL SERVICE to SYSTEM" 
layout: "post"
categories: ["Privilege Escalation"]
tags: ["Research","Privilege Escalation","Exploit"]
image: /assets/og/privilege_escalation.png
---

A DLL hijacking "vulnerability" in the __CDPSvc__ service was reported to Microsoft at least two times this year. As per their policy though, ___DLL planting issues that fall into the category of PATH directories DLL planting are treated as won't fix___ , which means that it won't be addressed (at least in the near future). This case is very similar to the IKEEXT one in Windows Vista/7/8. The big difference is that __CDPSvc__ runs as `LOCAL SERVICE` instead of `SYSTEM` so getting higher privileges requires an extra step.


## CDPSvc DLL Hijacking

Before we begin, I'll assume you know what __DLL hijacking__ is. It's probably one of the oldest and most basic privilege escalation techniques in Windows. Besides, the case of the __CDPSvc__ service was already well explained by [Nafiez](https://twitter.com/zeifan) in this article: [(MSRC Case 54347) Microsoft Windows Service Host (svchost) - Elevation of Privilege](https://nafiez.github.io/security/eop/2019/11/05/windows-service-host-process-eop.html).

Long story short, the __Connected Devices Platform Service__ (or CDPSvc) is a service which runs as `NT AUTHORITY\LOCAL SERVICE` and tries to load the missing __cdpsgshims.dll__ DLL on startup with a call to `LoadLibrary()`, without specifying its absolute path.

![](/assets/posts/2019-12-11-cdpsvc-dll-hijacking/03_ida-loadlibrary-not-found.png)

Therfore, following the __DLL search order of Windows__, it will first try to load it from the "system" folders and then go through the list of __directories which are stored in the `PATH` environment variable__. So, if one of these folders is configured with weak permissions, you could plant a "malicious" version of the DLL and thus execute arbitrary code in the context of `NT AUTHORITY\LOCAL SERVICE` upon reboot. 

![](/assets/posts/2019-12-11-cdpsvc-dll-hijacking/04_procmon.png)

__Note:__ the last `PATH` entry varies depending on the current user profile. This means that you will always see this folder as writable if you look at your own `PATH` variable in Windows 10. If you want to see the `PATH` variable of the System, you can check the registry with the following command: `reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /V Path`. 

That's it for the boring stuff. :sleeping: Now let's talk about some __Windows internals__ and lesser known __exploitation techniques__. :smiley:


## A Word (Or Maybe Two...) About Tokens And Impersonation 

In my previous article, I discussed the specific case of __service accounts__ running __without impersonation privileges__. As it turns out, it's not the case of __CDPSvc__ so we will be able to take advantage of this. However, I realize that I didn't say much about the implications of each impersonation privilege. It's not overly complicated but I know that it's easy to overlook this kind of things because there are so many other things to learn. 

Since I worked quite a bit on the inner working of tools such as [RottenPotato](https://github.com/foxglovesec/RottenPotato) or [JuicyPotato](https://github.com/ohpe/juicy-potato), I'd like to share what I learned in an hopefully clear and concise way. If you're already familiar with these concepts, you may skip to the next part. 

### Token Types 

First things first. Let's talk about __tokens__. There are 2 types of tokens: `Primary` tokens and `Impersonation` tokens. A `Primary` token represents the security information of a __process__ whereas an `Impersonation` token represents the security context of another user in a __thread__.

- __Primary__ token: one per process.  
- __Impersonation__ token: one per thread which impersonates another user.  

__Note:__ an `Impersonation` token can be converted to a `Primary` token with a call to `DuplicateTokenEx()`. 

### Impersonation Levels 

An `Impersonation` token comes with an __impersonation level__: `Anonymous`, `Identification`, `Impersonation` or `Delegation`. You can use a token for impersonation __only if__ it has an `Impersonation` or `Delegation` level associated with it.

- __Anonymous__: The server __cannot impersonate__ or __identify__ the client.
- __Identification__: The server can get the identity and privileges of the client, but __cannot impersonate__ the client.
- __Impersonation__: The server __can impersonate__ the client's security context on the local system.
- __Delegation__: The server __can impersonate__ the client's security context __on remote systems__.

### Impersonation 

Regarding the impersonation methods, there are 3 different ways to create a process as a different user in Windows as I far as I know. 

- __CreateProcessWithLogon()__ - ([documentation](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw))

This function doesn't require any specific privilege. Any user can call this function. However you must know the password of the target account. That's typically the method used by `runas`.

- __CreateProcessWithToken()__ - ([documentation](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw))

This function requires the `SeImpersonatePrivilege` privilege, which is enabled by default (for the `LOCAL SERVICE` account). As an input, it requires a `Primary` token.

- __CreateProcessAsUser()__ - ([documentation](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera))

This function requires the `SeAssignPrimaryTokenPrivilege` and `SeIncreaseQuotaPrivilege` privileges, which are both disabled by default (for the `LOCAL SERVICE` account) but only `SeAssignPrimaryTokenPrivilege` really needs to be enabled. `SeIncreaseQuotaPrivilege` will be transperently enabled/disabled during the API call. As an input, it also requires a `Primary` token.

| API function | Privilege(s) required | Input |
| :---: | :---: | :---: |
| `CreateProcessWithLogon()` | None | Domain / Username / Password |
| `CreateProcessWithToken()` | `SeImpersonatePrivilege` | Primary token |
| `CreateProcessAsUser()` | `SeAssignPrimaryTokenPrivilege` __AND__ `SeIncreaseQuotaPrivilege` | Primary token |
 
### The CDPSvc Case

As you can see on the below screenshot, the process in which __CDPSvc__ runs has the three privileges I've just talked about so it can impersonate any local user with `CreateProcessWithToken()` or `CreateProcessAsUser()` provided that you have a valid token for this user. 

![](/assets/posts/2019-12-11-cdpsvc-dll-hijacking/05_cdpsvc-process-token.png)

As a conclusion, we have the appropriate privileges to impersonate `NT AUTHORITY\SYSTEM`. The second thing we need is a valid token but how can we get one of them? :thinking:


## Bringing Back An Old Technique From The Dead: _Token Kidnapping_

In the old days of Windows, __all services ran as `SYSTEM`__, which means that when one of them was compromised all the other services and the host itself were also compromised. Therefore Microsoft added some segregation and introduced __two other accounts__ with less privileges: `NETWORK SERVICE` and `LOCAL SERVICE`. 

Unfortunately, this wasn't enough. Indeed, if a service running as `LOCAL SERVICE` was compromised for example, it could execute code in any other service running as the same user account, access its memory space and __extract privileged impersonation tokens__: this is the technique called __Token Kidnapping__, which was presented by [Cesar Cerrudo at several conferences in 2008](https://dl.packetstormsecurity.net/papers/presentations/TokenKidnapping.pdf). 

To counter this attack, Microsoft had to redesign the security model of the services. The main feature they implemented was __Service Isolation__. The idea is that each service __runs with a dedicated Security Identifier (SID)__. If you consider a service `A` with `SID_A` and a service `B` with `SID_B`, service `A` won't be able to access the ressources of service `B` anymore because the two processes are now running with two different identities (although it's the same account). 

Here is a quote from MS Blog, [Token Kidnapping in Windows](https://blogs.iis.net/nazim/token-kidnapping-in-windows).

> _The first issue to address is to make sure that two services running with the same identity not be able to access each other’s tokens freely. This concern has been mostly addressed with service hardening done in Windows Vista and above. There are some minor changes that would need to be done to strengthen service hardening to close some gaps identified during our investigation of this issue._

_OK so, basically, you're telling me that __Token Kidnapping__ is now useless because of __Service Isolation__. What's the point in talking about that then?_ :unamused:

~~Well, the fun fact about __CDPSvc__ is that it runs within a __shared process__ so __Service Isolation__ is almost pointless here since it can access the data of almost a dozen services.~~ __CDPSvc__ runs within a __shared process__ by default only if the machine has less than 3.5GB of RAM (See [Changes to Service Host grouping in Windows 10](https://docs.microsoft.com/en-us/windows/application-management/svchost-service-refactoring)). __The question is, among all these services, is there at least one that leaks interesting token handles?__

![](/assets/posts/2019-12-11-cdpsvc-dll-hijacking/06_process-services.png)

Let's take a look at the properties of the process once again. __Process Hacker__ provides a really nice feature. it can list all the __Handles__ that are open in a given process. 

![](/assets/posts/2019-12-11-cdpsvc-dll-hijacking/07_system-token-handles.png)

It looks like the process currently has __5 open Handles to `Impersonation` tokens which belong to the `SYSTEM` account__. How convenient! :sunglasses:

_Fine! How do we proceed?!_ :grin:

A __Handle__ is a reference to an object (such as a Process, a Thread, a File or a Token for example) but it doesn't hold the address of the object directly. It's just an entry in _an internally maintained table_ where the "actual" address is stored. So, it can be seen as an ID, which can be easily bruteforced. That's the idea behind the __Token Kidnapping__ technique. 

__Token Kidnapping__ consists in opening another process and then __bruteforcing the open Handles__ by duplicating them inside the current process. For each valid Handle, we check whether it's a Handle to a Token, if it's not the case, we go to the next one. 

If we find a __valid Token Handle__, we must check the following:

- The corresponding account is __`SYSTEM`__?  
- Is it an __Impersonation__ token?  
- The __Impersonation Level__ of the token is at least __Impersonation__?  

Of course, because of __Service Isolation__, this technique can't be applied to services running in different processes. However, if you are able to "inject" a DLL into one of these services, you can then __access the memory space of the corresponding process__ without any restrictions. So, you can apply the __same bruteforce technique__ from within the current process. And, once you've found a __proper impersonation token__, you can duplicate it and use the Windows API to __create a process as `NT AUTHORITY\SYSTEM`__. That's as simple as that.

No conclusion for this post. I just hope that you learned a few things. Here is the [link to my PoC](https://github.com/itm4n/CDPSvcDllHijacking).


## Demo 

![](/assets/posts/2019-12-11-cdpsvc-dll-hijacking/00_demo_2.gif)


## Links & Resources

- (MSRC Case 54347) Microsoft Windows Service Host (svchost) - Elevation of Privilege  
[https://nafiez.github.io/security/eop/2019/11/05/windows-service-host-process-eop.html](https://nafiez.github.io/security/eop/2019/11/05/windows-service-host-process-eop.html)

- Windows 10 Persistence via PATH directories - CDPSvc  
[https://www.a12d404.net/windows/2019/01/13/persistance-via-path-directories.html](https://www.a12d404.net/windows/2019/01/13/persistance-via-path-directories.html)

- Cesar Cerrudo - Token Kidnapping  
[https://dl.packetstormsecurity.net/papers/presentations/TokenKidnapping.pdf](https://dl.packetstormsecurity.net/papers/presentations/TokenKidnapping.pdf)

- MS Blog - Token Kidnapping in Windows  
[https://blogs.iis.net/nazim/token-kidnapping-in-windows](https://blogs.iis.net/nazim/token-kidnapping-in-windows)

- MSRC - Triaging a DLL planting vulnerability  
[https://msrc-blog.microsoft.com/2018/04/04/triaging-a-dll-planting-vulnerability/](https://msrc-blog.microsoft.com/2018/04/04/triaging-a-dll-planting-vulnerability/)

- MSDN - Access Tokens  
[https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens)

- MSDN - Impersonation Levels  
[https://docs.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels](https://docs.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)

