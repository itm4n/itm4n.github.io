---
title: "Do You Really Know About LSA Protection (RunAsPPL)?" 
layout: "post"
categories: [ "Defense Evasion" ]
tags: [ "Bypass", "Exploit" ]
---

When it comes to protecting against credentials theft on Windows, enabling LSA Protection (a.k.a. `RunAsPPL`) on `LSASS` may be considered as the very first recommendation to implement. But do you really know what a PPL is? In this post, I want to cover some core concepts about _Protected Processes_ and also prepare the ground for a follow-up article that will be released in the coming days.


## Introduction

When you think about it, `RunAsPPL` for `LSASS` is a true quick win. It is very easy to configure as the only thing you have to do is add a simple value in the registry and reboot. Like any other protection though, it is not bulletproof and it is not sufficient on its own, but it is still particularly efficient. Attackers will have to use some relatively advanced tricks if they want to work around it, which ultimately increases their chance of being detected.

Therefore, as a security consultant, this is one of the top recommendations I usually give to a client. However, from a client's perspective, I noticed that this protection tends to be confused with [Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard), which is completely different. I think that this confusion comes from the fact that the latter seems to provide a more robust mechanism although [Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard) and [LSA Protection](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection) are actually complementary.

But of course, as a consultant, you have to explain these concepts if you want to convince a client that they should implement both recommendations. Some time ago, I had to give such explanation so, without going into too much detail, I think I said something like this about [LSA Protection](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection): "_only a digitally signed binary can access a protected process_". You probably noticed that this sentence does not make much sense. This is how I realized that I didn't really know how Protected Processes worked. So, I did some research and I found some really interesting things along the way, hence why I wanted to write about it.

__Disclaimer --__ Most of the concepts I discuss in this post are already covered by the [official documentation](https://docs.microsoft.com/) and the book [_Windows Internals 7th edition (Part 1)_](https://docs.microsoft.com/en-us/sysinternals/resources/windows-internals), which were my two main sources of information. The objective of this blog post is not to paraphrase them but rather gather the information which I think is the most valuable from a security consultant's perspective.

## How to Enable LSA Protection (RunAsPPL)

As mentioned previously, `RunAsPPL` is very easy to enable. The procedure is detailed in the official documentation and has also been covered in many blog posts before.

If you want to enable it within a corporate environment, you should follow the procedure provided by Microsoft and create a _Group Policy_: [_Configuring Additional LSA Protection_](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection#to-enable-lsa-protection-using-group-policy). But if you just want to enable it manually on a single machine, you just have to:

1. open the _Registry Editor_ (`regedit.exe`) as an Administrator;
2. open the key `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`;
3. add the `DWORD` value `RunAsPPL` and set it to `1`;
4. reboot.

![](/assets/posts/2021-04-07-lsass-runasppl/01_regedit-runasppl.png)

That's it! You are done!

Before applying this setting throughout an entire corporate environment, there are two particular cases to consider though. They are both described in the [official documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection). If the answer to at least one of the two following questions is "_yes_" then you need to take some precautions.

- Do you use any __third-party authentication module__?
- Do you use __UEFI__ and/or ___Secure Boot___?

__Third-party authentication module --__ If a third-party authentication module is required, such as in the case of a Smart Card Reader for example, you should make sure that they meet the requirements that are listed here: [_Protected process requirements for plug-ins or drivers_](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection#protected-process-requirements-for-plug-ins-or-drivers). Basically, the module must be _digitally signed with a Microsoft signature_ and it must comply with the _Microsoft Security Development Lifecycle (SDL)_. The documentation also contains some instructions on how to set up an _Audit Policy_ prior to the rollout phase to determine whether such module would be blocked if `RunAsPPL` were enabled.

__Secure Boot --__ If _Secure Boot_ is enabled, which is usually the case with modern laptops for example, there is one important thing to be aware of. When `RunAsPPL` is enabled, _the setting is stored in the firmware_, in a UEFI variable. This means that, once the registry key is set and the machine has rebooted, deleting the newly added registry value will have no effect and `RunAsPPL` will remain enabled. If you want to disable the protection, you have to follow the procedure provided by Microsoft here: [_To disable LSA protection_](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection#to-disable-lsa-protection).

## You Shall Not Pass!

By now, I assume you all know that `RunAsPPL` is an effective protection against tools such as [Mimikatz](https://github.com/gentilkiwi/mimikatz) (more about that in the next parts) or [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) from the [Windows Sysinternals](https://docs.microsoft.com/en-us/sysinternals/) tools suite for example. An output such as the one below should therefore look familiar.

![](/assets/posts/2021-04-07-lsass-runasppl/02_mimikatz-logonpasswords-access-denied.png)

This screenshot shows several important things:

- the current user is a member of the default _Administrators_ group;
- the current user has `SeDebugPrivilege` (although it is currently disabled);
- the command `privilege::debug` in _Mimikatz_ successfully enabled `SeDebugPrivilege`;
- the command `sekurlsa::logonpasswords` failed with the error code `0x00000005`.

So, despite all the privileges the current user has, the command failed. To understand why, we should take a look at the `kuhl_m_sekurlsa_acquireLSA()` function in [mimikatz/modules/sekurlsa/kuhl_m_sekurlsa.c](https://github.com/gentilkiwi/mimikatz/blob/fe4e98405589e96ed6de5e05ce3c872f8108c0a0/mimikatz/modules/sekurlsa/kuhl_m_sekurlsa.c). Here is a simplified version of the code that shows only the part we are interested in.

```cpp
HANDLE hData = NULL;
DWORD pid;
DWORD processRights = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;

kull_m_process_getProcessIdForName(L"lsass.exe", &pid);
hData = OpenProcess(processRights, FALSE, pid);

if (hData && hData != INVALID_HANDLE_VALUE) {
    // if OpenProcess OK
} else {
    PRINT_ERROR_AUTO(L"Handle on memory");
}
```

In this code snippet, `PRINT_ERROR_AUTO` is a macro that basically prints the name of the function which failed along with the error code. The error code itself is retrieved by invoking `GetLastError()`. For those of you who are not familiar with the way the Windows API works, you just have to know that `SetLastError()` and `GetLastError()` are two _Win32_ functions that allow you to set and get the last standard error code. The first 500 codes are listed here: [_System Error Codes (0-499)_](https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-).

Apart from that, the rest of the code is pretty straightforward. It first gets the PID of the process called `lsass.exe` and then, it tries to open it (i.e. get a _process handle_) with the flags `PROCESS_VM_READ` and `PROCESS_QUERY_INFORMATION` by invoking the _Win32_ function `OpenProcess`. What we can see on the previous screenshot is that this function failed with the error code `0x00000005`, which simply means "_Access is denied_". This confirms that, once `RunAsPPL` is enabled, even an administrator with `SeDebugPrivilege` cannot open `LSASS` with the required access flags.

All the things I have explained so far can be considered common knowledge as they have been discussed in many other blog posts or _pentest_ cheat sheets before. But I had to do this recap to make sure we are all on the same page and also to introduce the following parts.

## Bypassing RunAsPPL with Currently Known Techniques

At the time of writing this blog post, there are three main known techniques for bypassing `RunAsPPL` and accessing the memory of `lsass.exe` (or any other PPL in general). Once again, this has already been discussed in other blog posts, so I will try to keep this short.

### Technique 1 -- The Revenge of the Kiwi

In the previous part, I stated that `RunAsPPL` effectively prevented [Mimikatz](https://github.com/gentilkiwi/mimikatz) from accessing the memory of `lsass.exe`, but this tool is actually also the most commonly known technique for bypassing it. 

To do so, [Mimikatz](https://github.com/gentilkiwi/mimikatz) uses a __digitally signed driver__ to remove the protection flag of the Process object in the Kernel. The file `mimidrv.sys` must be located in the current folder in order to be loaded as a Kernel driver service using the command `!+`. Then, you can use the command `!processprotect` to remove the protection and finally access `lsass.exe`.

```console
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

![](/assets/posts/2021-04-07-lsass-runasppl/03_mimikatz-mimidrv-processprotect-remove.png)

Once you are done, you can even "_restore_" the protection using the same command, but without the `/remove` argument and finally unload the driver with `!-`.

```console
mimikatz # !processprotect /process:lsass.exe
mimikatz # !-
```

![](/assets/posts/2021-04-07-lsass-runasppl/04_mimikatz-mimidrv-processprotect.png)

There is one thing to be aware of if you do that though! You have to know that [Mimikatz](https://github.com/gentilkiwi/mimikatz) __does not restore the protection level to its original level__. The two screenshots below show the protection level of the `lsass.exe` process before and after issuing the command `!processprotect /process:lsass.exe`. As you can see, when `RunAsPPL` is enabled, the protection level is `PsProtectedSignerLsa-Light` whereas it is `PsProtectedSignerWinTcb` after the protection was _restored_  by [Mimikatz](https://github.com/gentilkiwi/mimikatz). In a way, this renders the system even more secure than it was as you will see in the next part but it could also have some undesired side effects.

![](/assets/posts/2021-04-07-lsass-runasppl/05_procexp-lsass-protection-level-runasppl.png)

![](/assets/posts/2021-04-07-lsass-runasppl/06_procexp-lsass-protection-level-altered.png)

### Technique 2 -- Bring You Own Driver

The major drawback of the previous method is that it can be easily detected by an antivirus. Even if you are able to execute [Mimikatz](https://github.com/gentilkiwi/mimikatz) in-memory for example, you still have to copy `mimidrv.sys` onto the target. At this point, you could consider compiling a custom version of the driver to evade signature-based detection, but this will also break the digital signature of the file. So, unless you are willing to pay a few hundred dollars to get your new driver signed, this will not do.

If you don't want to go through the official signing process, there is a clever trick you can use. This trick consists in loading an _official_ and vulnerable driver that can be exploited to run arbitrary code in the Kernel. Once the driver is loaded it can be exploited from User-land to load an unsigned driver for example. This technique is implemented in [gdrv-loader](https://github.com/alxbrn/gdrv-loader) and [PPLKiller](https://github.com/RedCursorSecurityConsulting/PPLKiller) for instance.

### Technique 3 -- Python & Katz

The last two techniques both rely on the use of a driver to execute arbitrary code in the Kernel and disable the Process protection. Such technique is still very dangerous, make one mistake and you trigger a BSOD.

More recently though, [SkelSec](https://twitter.com/skelsec) presented an alternative method for accessing `lsass.exe`. In an article entitled [Duping AV with handles](https://skelsec.medium.com/duping-av-with-handles-537ef985eb03), he presented a _way to bypass AV detection/blocking access to LSASS process_.

If you want to access LSASS' memory, the first thing you have to do is invoke `OpenProcess` to get a handle with the appropriate rights on the Process object. Therefore, some AV software may block such attempt, thus effectively killing the attack in its early stage. The idea behind the technique described by [SkelSec](https://twitter.com/skelsec) is simple: _simply do not invoke_ `OpenProcess`. But how do you get the initial handle then? The answer came from the following observation. Sometimes, other processes, such as in the case of Antivirus software, already have an opened handle on the LSASS process in their memory space. So, as an administrator with debug privileges, you could copy this handle into you own process and then use it to access LSASS. 

It turns out this technique serves another purpose. It can also be used to bypass `RunAsPPL` because some unprotected processes may have obtained a handle on the LSASS process by another mean, using a driver for instance. In which case you can use [pypykatz](https://github.com/skelsec/pypykatz) with the following command.

```console
pypykatz live lsa --method handledup
```

On some occasions, this method worked perfectly fine for me but it is still a bit random. The chance of success highly depends on the target environment, which explains why I was not able to reproduce it on my lab machine.

## What are PPL Processes?

Here comes the interesting part. In the previous paragraphs, I intentionally glossed over some key concepts. I chose to present all the things that are commonly known first so I can explain them into more detail here. 

### A Long Time Ago in a Galaxy Far, Far Away...

OK, it was not that long ago and it was not that far away either. But still, the history behind PPLs is quite interesting and definitely worth mentioning. 

First things first, __PPL__ means ___Protected Process Light___ but, before that, there were just ___Protected Processes___. The concept of _Protected Process_ was introduced with __Windows Vista__ / __Server 2008__ and its objective was not to protect your data or your credentials. Its initial objective was to protect media content and comply with __DRM__ (_Digital Rights Management_) requirements. Microsoft developed this mechanism so that your media player could read a Blu-ray for instance, while preventing you from copying its content. At the time, the requirement was that the image file (i.e. the executable file) had to _be digitally signed with a special Windows Media Certificate_ (as explained in the "_Protected Processes_" part of [_Windows Internals_](https://docs.microsoft.com/en-us/sysinternals/resources/windows-internals)).

In practice, a _Protected Process_ can be accessed by an unprotected process only with very limited privileges: `PROCESS_QUERY_LIMITED_INFORMATION`, `PROCESS_SET_LIMITED_INFORMATION`, `PROCESS_TERMINATE` and `PROCESS_SUSPEND_RESUME`. This set can even be reduced for some highly-sensitive processes.

A few years later, starting with __Windows 8.1__ / __Server 2012 R2__, Microsoft introduced the concept of __Protected Process Light__. PPL is actually an extension of the previous _Protected Process_ model and adds the concept of "Protection level", which basically means that some PP(L) processes can be more protected than others.

### Protection Levels

The protection level of a process was added to the `EPROCESS` kernel structure and is more specifically stored in its `Protection` member. This `Protection` member is a `PS_PROTECTION` structure and is documented [here](https://docs.microsoft.com/en-us/windows/win32/procthread/zwqueryinformationprocess).

```c
typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type   : 3;
            UCHAR Audit  : 1;                  // Reserved
            UCHAR Signer : 4;
        };
    };
} PS_PROTECTION, *PPS_PROTECTION;
```

Although it is represented as a structure, all the information is stored in the two nibbles of a single byte (`Level` is a `UCHAR`, i.e. an `unsigned char`). The first 3 bits represent the protection `Type` (see `PS_PROTECTED_TYPE` below). It defines whether the process is a PP or a PPL. The last 4 bits represent the `Signer` type (see `PS_PROTECTED_SIGNER` below), i.e. the actual level of protection.

```c
typedef enum _PS_PROTECTED_TYPE {
    PsProtectedTypeNone = 0,
    PsProtectedTypeProtectedLight = 1,
    PsProtectedTypeProtected = 2
} PS_PROTECTED_TYPE, *PPS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER {
    PsProtectedSignerNone = 0,      // 0
    PsProtectedSignerAuthenticode,  // 1
    PsProtectedSignerCodeGen,       // 2
    PsProtectedSignerAntimalware,   // 3
    PsProtectedSignerLsa,           // 4
    PsProtectedSignerWindows,       // 5
    PsProtectedSignerWinTcb,        // 6
    PsProtectedSignerWinSystem,     // 7
    PsProtectedSignerApp,           // 8
    PsProtectedSignerMax            // 9
} PS_PROTECTED_SIGNER, *PPS_PROTECTED_SIGNER;
```

As you probably guessed, a process' protection level is defined by a combination of these two values. The below table lists the most common combinations.

| Protection level | Value | Signer | Type |
| --- | :---: | --- | --- |
| `PS_PROTECTED_SYSTEM` | 0x72 | WinSystem (7) | Protected (2) |
| `PS_PROTECTED_WINTCB` | 0x62 | WinTcb (6) | Protected (2) |
| `PS_PROTECTED_WINDOWS` | 0x52 | Windows (5) | Protected (2) |
| `PS_PROTECTED_AUTHENTICODE` | 0x12 | Authenticode (1) | Protected (2) |
| `PS_PROTECTED_WINTCB_LIGHT` | 0x61 | WinTcb (6) | Protected Light (1) |
| `PS_PROTECTED_WINDOWS_LIGHT` | 0x51 | Windows (5) | Protected Light (1) |
| `PS_PROTECTED_LSA_LIGHT` | 0x41 | Lsa (4) | Protected Light (1) |
| `PS_PROTECTED_ANTIMALWARE_LIGHT` | 0x31 | Antimalware (3) | Protected Light (1) |
| `PS_PROTECTED_AUTHENTICODE_LIGHT` | 0x11 | Authenticode (1) | Protected Light (1) |

### Signer Types

In the early days of _Protected Processes_, the protection level was binary, either a process was protected or it was not. We saw that this changed when PPL were introduced with Windows NT 6.3. Both PP and PPL now have a protection level which is determined by a signer level as described previously. Therefore, another interesting thing to know is how the signer type and the protection level are determined.

The answer to this question is quite simple. Although there are some exceptions, the signer level is most commonly determined by a special field in the file's digital certificate: Enhanced Key Usage (EKU).

![](/assets/posts/2021-04-07-lsass-runasppl/07_certificates-eku-ppl-level.png)

On this screenshot, you can see two examples, `wininit.exe` on the left and `SgrmBroker.exe` on the right. In both cases, we can see that the EKU field contains the OID that represents the `Windows TCB Component` signer type. The second highlighted OID represents the protection level, which is `Protected Process Light` in the case of `wininit.exe` and `Protected Process` in the case of `SgrmBroker.exe`. As a result, we know that the latter can be executed as a PP whereas the former can only be executed as a PPL. However, they will both have the `WinTcb` level.

### Protection Precedence

The last key aspect that needs to be discussed is the _Protection Precedence_. In the "_Protected Process Light (PPL)_ part of [_Windows Internals 7th Edition Part 1_](https://docs.microsoft.com/en-us/sysinternals/resources/windows-internals), you can read the following:

> _When interpreting the power of a process, keep in mind that first, protected processes always trump PPLs, and that next, higher-value signer processes have access to lower ones, but not vice versa._

In other words:

- a PP can open a PP or a PPL with full access, as long as its signer level is greater or equal;
- a PPL can open another PPL with full access, as long as its signer level is greater or equal;
- a PPL cannot open a PP with full access, regardless of its signer level.

__Note:__ it goes without saying that the ACL checks still apply. Being a _Protected Process_ does not grant you _super powers_. If you are running a protected process as a low privileged user, you will not be able to _magically_ access other users' processes. It's an additional protection.

To illustrate this, I picked 3 easily identifiable processes / image files: 

- `wininit.exe` -- Session 0 initilization
- `lsass.exe` -- LSASS process
- `MsMpEng.exe` -- Windows Defender service

![](/assets/posts/2021-04-07-lsass-runasppl/08_procexp-protection-levels.png)

| Pr. | Process | Type | Signer | Level |
| :---: | --- | --- | --- | --- |
| __1__ | `wininit.exe` | Protected Light | WinTcb | `PsProtectedSignerWinTcb-Light` |
| __2__ | `lsass.exe` | Protected Light | Lsa | `PsProtectedSignerLsa-Light` |
| __3__ | `MsMpEng.exe` | Protected Light | Antimalware | `PsProtectedSignerAntimalware-Light` |

These 3 PPLs are running as `NT AUTHORITY\SYSTEM` with `SeDebugPrivilege` so user rights are not a concern in this example. This all comes down to the protection level. As `wininit.exe` has the signer type `WinTcb`, which is the highest possible value for a PPL, it could access the two other processes. Then, `lsass.exe` could access `MsMpEng.exe` as the signer level `Lsa` is higher than `Antimalware`. Finally, `MsMpEng.exe` can access none of the two other processes because it has the lowest level.

## Conclusion

In the end, the concept of _Protected Process (Light)_ remains a Userland protection. It was designed to prevent normal applications, even with administrator privileges, from accessing protected processes. This explains why most common techniques for bypassing such protection require the use of a driver. If you are able to execute arbitrary code in the Kernel, you can do (almost) whatever you want and you could well completely disable the protection of any _Protected Process_. Of course, this has become a bit more complicated over the years as you are now required to load a digitally signed driver, but this restriction can be worked around as we saw.

In this post, we also saw that this concept has evolved from a basic unprotected/protected model to a hierarchical model, in which some processes can be more protected than others. In particular, we saw that "LSASS" has its own protection level -- `PsProtectedSignerLsa-Light`. This means that a process with a higher protection level (e.g.: "WININIT"), would still be able to open it with full access.

There is one aspect of PP/PPL that I did not mention though. The "L" in "PPL" is here for a reason. Indeed, with the concept of _Protected Process Light_, the overall security model was partially loosened, which opens some doors for Userland exploits. In the coming days, I will release the second part of this post to discuss one of these techniques. This will also be accompanied by the release of a new tool -- __PPLdump__. As its name implies, this tool provides the ability for a local administrator to dump the memory of any PPL process, using only Userland tricks.

Lastly, I would like to mention that this Research & Development work was partly done in the context of my job at [SCRT](https://www.scrt.ch). So, the next part will be published on their [blog](https://blog.scrt.ch/), but I'll keep you posted on Twitter. The best is yet to come, so stay tuned!

__Update 2021-04-25__ -- The second part is now available here: [Bypassing LSA Protection in Userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/)

## Links & Resources

- Microsoft - How to configure additional LSA protection of credentials  
[https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)

- Windows Internals 7th edition (Part 1)  
[https://docs.microsoft.com/en-us/sysinternals/resources/windows-internals](https://docs.microsoft.com/en-us/sysinternals/resources/windows-internals)