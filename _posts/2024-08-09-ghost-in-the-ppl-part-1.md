---
title: "Ghost in the PPL Part 1: BYOVDLL"
layout: "post"
categories: ["Defense Evasion"]
tags: ["Bypass","Exploit","Research"]
image: /assets/og/defense_evasion.png
---

In this series of blog posts, I will explore yet another avenue for bypassing LSA Protection in Userland. I will also detail the biggest challenges I faced while developing a proof-of-concept, and discuss some novel techniques and tricks to load an arbitrary DLL in LSASS, or even dump its memory.

## Bring Your Own Vulnerable DLL (BYOVDLL)

In July 2022, Microsoft brought some changes to their Protected Process Light (PPL) implementation to mitigate a well-known flaw, originally discovered by [Alex Ionescu](https://infosec.exchange/@aionescu) and [James Forshaw](https://infosec.exchange/@tiraniddo) a few years prior, allowing this protection to be easily bypassed without the need to execute code in the Kernel.

This change effectively broke my [PPLdump](https://github.com/itm4n/PPLdump) proof-of-concept (PoC) but, in October 2022, [Gabriel Landau](https://twitter.com/GabrielLandau) posted a message on Twitter in which he alluded to the fact that this wasn't completely true. To prove his point, he attached a screenshot showing how he used a technique called "Bring Your Own Vulnerable DLL" to bring the original vulnerability back from the dead, and run [PPLdump](https://github.com/itm4n/PPLdump) again without any modification.

![https://twitter.com/GabrielLandau/status/1580067594568364032](/assets/posts/2024-08-09-ghost-in-the-ppl-part-1/twitter-ppldump-byovdll.png)
_[https://twitter.com/GabrielLandau/status/1580067594568364032](https://twitter.com/GabrielLandau/status/1580067594568364032)_

Since then, I kept thinking about this concept, and how I could use it to execute arbitrary code within a protected process using other DLLs, and most importantly, without having to reboot.

## Choosing our Target

As a reminder, there are currently two "protection levels": Protected Process (PP) and Protected Process Light (PPL). Each protection level has its own set of "signer types", such as "Windows", "WinTcb", or even "Lsa" in the case of LSASS. The combination of these two values defines a hierarchy, thereby making some processes "more protected" than others. Thus, we want to target a PP with the highest signer type available, but those processes usually present a smaller attack surface than PPLs, such as LSASS when [LSA Protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection) is enabled. Besides, LSASS is also a more appealing target when it comes to extracting in-memory credentials during post-exploitation. To illustrate what I mean by that, I listed all the services that may run within this process, as shown below.

![PowerShell - List of services that may run in LSASS](/assets/posts/2024-08-09-ghost-in-the-ppl-part-1/powershell-services-lsass-shared-process.png)
_PowerShell - List of services that may run in LSASS_

Alternatively, [System Informer](https://systeminformer.sourceforge.io/) can be used to list services that are actually running within LSASS.

![System Informer - List of services running in LSASS](/assets/posts/2024-08-09-ghost-in-the-ppl-part-1/system-informer-lsass-services.png)
_System Informer - List of services running in LSASS_

Because I'm constantly monitoring for public documentation, PoCs and exploits for Elevation of Privilege (EoP) bugs, I knew that the CNG Key Isolation service, a.k.a. "KeyIso", was a good target. More specifically, I knew that I wanted to target this service when I saw the blog post [Isolate me from sandbox - Explore elevation of privilege of CNG Key Isolation](https://whereisk0shl.top/post/isolate-me-from-sandbox-explore-elevation-of-privilege-of-cng-key-isolation) by [k0shl](https://twitter.com/KeyZ3r0), and the PoC exploit published by [Y3A](https://github.com/Y3A) on GitHub [here](https://github.com/Y3A/CVE-2023-28229), as they would offer the initial building blocks I needed for what I had in mind.

In their blog post, [k0shl](https://twitter.com/KeyZ3r0) actually discusses two separate bugs: an out-of-bound (OOB) read ([CVE-2023-36906](https://msrc.microsoft.com/update-guide/en-us/advisory/CVE-2023-36906)), which serves as an information disclosure primitive to then exploit a use-after-free (UAF) flaw ([CVE-2023-28229](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2023-28229)). I won't cover the details of these two issues, nor the implementation of the PoC exploit, as it goes way beyond my knowledge and skills. The only thing you need to know for now is that these bugs can be abused through a subset of RPC procedures exposed by the KeyIso service, and that their successful exploitation eventually leads to the control of a CALL instruction's target (`RAX` register), and the first argument (`RCX` register).

## Loading a Vulnerable Version of the KeyIso DLL

The `ImagePath` configured for the KeyIso service is the path of `lsass.exe`. This is because its type is `Win32ShareProcess` (32), which means it shares the same process as other services, such as EFS or VaultSvc, as we saw earlier.

![Registry - Configuration of the KeyIso service](/assets/posts/2024-08-09-ghost-in-the-ppl-part-1/registry-keyiso-imagepath.png)
_Registry - Configuration of the KeyIso service_

The actual path of the module containing the implementation of the service is set in the `Parameters` key, and has the value `%SystemRoot%\system32\keyiso.dll`.

![Registry - Parameters of the KeyIso service](/assets/posts/2024-08-09-ghost-in-the-ppl-part-1/registry-keyiso-servicedll.png)
_Registry - Parameters of the KeyIso service_

Lastly, the default DACL of this key grants `Full Control` to the `Administrators` group, so we don't even need to impersonate `Trusted Installer` to modify it. If we want to load a vulnerable version of this DLL in LSASS, we can just stop the service, change the path of the DLL in the Registry, and restart it.

![Registry - Permissions of the `Parameters` key](/assets/posts/2024-08-09-ghost-in-the-ppl-part-1/registry-keyiso-servicedll-permissions.png)
_Registry - Permissions of the `Parameters` key_

I did just that, and got the system error code 577 (`ERROR_INVALID_IMAGE_HASH`) - "Windows cannot verify the digital signature for this file" - when trying to start the service. This is the error code you are supposed to get when attempting to load a non Microsoft-signed DLL in a PP(L). In my case though, I'm using a legitimate Windows DLL, so what's causing this issue?

![Attempting to start the KeyIso service with `net.exe`](/assets/posts/2024-08-09-ghost-in-the-ppl-part-1/net-start-keyiso-fail-signature.png)
_Attempting to start the KeyIso service with `net.exe`_

To find out, we should first compare the signatures of the built-in `keyiso.dll`, and the imported one, using the PowerShell command `Get-AuthenticodeSignature`. In the case of the imported DLL, the status is just `NotSigned`, which is consistent with the previous error message at least...

![PowerShell - Comparison of Authenticode signatures](/assets/posts/2024-08-09-ghost-in-the-ppl-part-1/powershell-keyiso-signature-comparison.png)
_PowerShell - Comparison of Authenticode signatures_

The reason why Windows can't find the DLL's signature is simply because it isn't stored in the file. For a binary such as `lsass.exe`, the signature is directly embedded into the file, but for most DLLs, this is not the case. We can see that by comparing the properties of `lsass.exe` and `keyiso.dll` for instance. One has a "Digital Signatures" tab, but not the other. So, where is the signature stored?

![Properties of `lsass.exe` and `keyiso.dll`](/assets/posts/2024-08-09-ghost-in-the-ppl-part-1/lsass-keyiso-files-properties.png)
_Properties of `lsass.exe` and `keyiso.dll`_

A more common way to store file signatures on Windows consists in using [Catalog Files](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/catalog-files). As explained in the documentation, "A catalog file contains a collection of cryptographic hashes, or thumbprints.", and "Each thumbprint corresponds to a file that is included in the collection.". One way to see which catalog file is associated to a given binary is to use [SigCheck](https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck) with the option `-i`.

![Checking the signature of `keyiso.dll` with `SigCheck.exe`](/assets/posts/2024-08-09-ghost-in-the-ppl-part-1/sigcheck-keyiso-catalog-file.png)
_Checking the signature of `keyiso.dll` with `SigCheck.exe`_

The screenshot above was taken on a Windows 11 machine manually updated with the package `KB5023778` to get the version `10.0.22621.1485` of `keyiso.dll`, the version prior to the security patch for CVE-2023-28229 and CVE-2023-36906.

![Applying the update package `KB5023778` on Windows 11](/assets/posts/2024-08-09-ghost-in-the-ppl-part-1/windows-update-applying-patch.png)
_Applying the update package `KB5023778` on Windows 11_

We can thus extract both the vulnerable DLL and the catalog file containing its signature. After copying the catalog file to the `CatRoot` folder of a fully updated Windows 11 machine, we can confirm that the signature of the imported `keyiso.dll` file is now recognized by the OS.

![Checking the signature of an imported `keyiso.dll` file](/assets/posts/2024-08-09-ghost-in-the-ppl-part-1/sigcheck-after-catalog-added.png)
_Checking the signature of an imported `keyiso.dll` file_

And there we have it, a vulnerable version of `keyiso.dll` loaded in our protected LSASS process!

![Starting the KeyIso service using a vulnerable DLL](/assets/posts/2024-08-09-ghost-in-the-ppl-part-1/net-start-with-vuln-dll-successful.png)
_Starting the KeyIso service using a vulnerable DLL_

## Testing the Information Disclosure (CVE-2023-36906)

Before going any further, I wanted to make sure that the initial [proof-of-concept](https://github.com/Y3A/CVE-2023-28229) worked as intended. However, even after running the exploit a few times, it still failed to go past the information disclosure step.

![Running the original Proof-of-Concept exploit](/assets/posts/2024-08-09-ghost-in-the-ppl-part-1/exploit-info-leak-fail.png)
_Running the original Proof-of-Concept exploit_

The information disclosure vulnerability is due to an improper bound check in the function `SPCryptGetProviderProperty`, which can be abused by first calling `SPCryptSetProviderProperty` with a specially crafted input buffer. What I didn't realize initially was that these two functions are not implemented in `keyiso.dll`, but in `ncryptprov.dll`.

The DLL `ncryptprov.dll` contains the implementation of the [Microsoft Software Key Storage Provider](https://learn.microsoft.com/en-us/windows/win32/seccertenroll/cng-key-storage-providers). We can see that by opening the Registry editor, and checking the content of the Image value in its properties, as highlighted on the screenshot below.

![Registry - Settings of the "Microsoft Software Key Storage Provider"](/assets/posts/2024-08-09-ghost-in-the-ppl-part-1/registry-ms-software-key-storage-provider.png)
_Registry - Settings of the "Microsoft Software Key Storage Provider"_

This is a problem because `ncryptprov.dll` is automatically loaded by LSASS when it starts. We could modify the value of the `Image` property in the registry to specify the name of a vulnerable version of this DLL instead, but then we would still have to restart the machine.

![System Informer - DLL `ncryptprov.dll` loaded in LSASS](/assets/posts/2024-08-09-ghost-in-the-ppl-part-1/system-informer-lsass-ncryptprov-loaded.png)
_System Informer - DLL `ncryptprov.dll` loaded in LSASS_

Therefore, for this exploit to work, we also need to figure out a way to load a vulnerable version of `ncryptprov.dll`.

## Registering a Key Storage Provider

Fortunately, we don't need to change the configuration of the built-in Microsoft Software Key Storage Provider (KSP) to load a vulnerable version of `ncryptprov.dll`. Instead, we should theoretically be able to register a new KSP. My only worry was whether it could be done without a machine reboot.

I couldn't find any official documentation explaining how to register a Key Storage Provider, so my idea was to find a third-party provider and analyze its installation process to find out how to do it through reverse engineering. I quickly came across the documentation of [YubiHSM 2](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-ksp-windows-guide.html), and more specifically its Windows installation and configuration. After installing it, I observed that a new provider named "YubiHSM Key Storage Provider" was indeed available, and I was also able to instantiate it with a call to the documented Win32 API `NCryptOpenStorageProvider`.

```cpp
NCRYPT_PROV_HANDLE hProvider = NULL;
SECURITY_STATUS status;

status = NCryptOpenStorageProvider(&hProvider, argv[1], 0);
wprintf(L"NCryptOpenStorageProvider: 0x%08x\n", status);

if (status == ERROR_SUCCESS) {
    status = NCryptFreeObject(hProvider);
    wprintf(L"NCryptFreeObject: 0x%08x\n", status);
}
```

![Opening a third-party KSP with `NCryptOpenStorageProvider`](/assets/posts/2024-08-09-ghost-in-the-ppl-part-1/loading-yubihsm-ksp.png)
_Opening a third-party KSP with `NCryptOpenStorageProvider`_

This is the confirmation that it is possible to register a KSP without a reboot. The question is how to do that programmatically? My initial idea was to naively replicate the registry structure, but without great surprise, this did not work. So, instead, I monitored the installation process of the YubiHSM MSI package with [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon).

![Process Monitor - Analyzing the installation process of YubiHSM](/assets/posts/2024-08-09-ghost-in-the-ppl-part-1/procmon-msiexec-bcryptregisterprovider.png)
_Process Monitor - Analyzing the installation process of YubiHSM_

This is how I found that the KSP is registered using the API `BCryptRegisterProvider`. The name sounded familiar to some `BCrypt*` functions I already knew about, so why didn't I find it in the public Microsoft documentation, you might ask. As it turns out, the header file `bcrypt.h` is largely [documented](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/), but there is no reference to `BCryptRegisterProvider` in there.

![Online documentation of the header file `bcrypt.h`](/assets/posts/2024-08-09-ghost-in-the-ppl-part-1/bcrypt-documentation.png)
_Online documentation of the header file `bcrypt.h`_

Part of the answer came from a GitHub [issue](https://github.com/virtio-win/kvm-guest-drivers-windows/issues/549) on the [virtio-win](https://github.com/virtio-win) project, which provides Windows drivers for KVM guest virtual machines. From the thread of messages, I understood that `BCryptRegisterProvider` is defined in the header file `bcrypt_provider.h`, and that this file is provided through the [Cryptographic Provider Development Kit](https://www.microsoft.com/en-us/download/details.aspx?id=30688) (CPDK), which needs to be installed on top of the Windows SDK.

![Installation of the Cryptographic Provider Development Kit](/assets/posts/2024-08-09-ghost-in-the-ppl-part-1/cpdk-installation.png)
_Installation of the Cryptographic Provider Development Kit_

To use it, you have to update the include path of your C/C++ project and add the entry `$(WindowsSdkDir)Cryptographic Provider Development Kit\Include`.

![Visual Studio - Adding the CPDK to the include path of a project](/assets/posts/2024-08-09-ghost-in-the-ppl-part-1/project-include-path-update-cpdk.png)
_Visual Studio - Adding the CPDK to the include path of a project_

Just knowing the name of the API, without official documentation, is not ideal though. We can get some information about its usage from the header file, but we can also search for sample code on the Internet. One instance I found is in the [Google Cloud Platform](https://github.com/GoogleCloudPlatform) (GCP)'s project [compute-windows-drivers](https://github.com/GoogleCloudPlatform/compute-windows-drivers) on GitHub, in the file [`viorngci.c`](https://github.com/GoogleCloudPlatform/compute-windows-drivers/blob/master/viorng/coinstaller/viorngci.c#L105).

![Sample code from GCP showing how to register a KSP](/assets/posts/2024-08-09-ghost-in-the-ppl-part-1/github-viorngci-register-ksp.png)
_Sample code from GCP showing how to register a KSP_

Below is a slightly simplified version of the code I used to register and unregister my own Key Storage Provider, based on the code of the GCP project.

```cpp
NTSTATUS WINAPI RegisterKeyStorageProvider(LPCWSTR ProviderName, LPCWSTR ImageName)
{
    NTSTATUS status = 0;
    CRYPT_PROVIDER_REG provider_reg;
    CRYPT_IMAGE_REG image_reg;
    CRYPT_INTERFACE_REG interface_reg;
    PCRYPT_INTERFACE_REG interfaces[1];
    PWSTR pwszFunctions[1];

    pwszFunctions[0] = const_cast<wchar_t*>(NCRYPT_KEY_STORAGE_ALGORITHM);

    interface_reg.dwInterface = NCRYPT_KEY_STORAGE_INTERFACE;
    interface_reg.dwFlags = CRYPT_LOCAL;
    interface_reg.cFunctions = 1;
    interface_reg.rgpszFunctions = pwszFunctions;

    interfaces[0] = &interface_reg;

    image_reg.pszImage = const_cast<wchar_t*>(ImageName);
    image_reg.cInterfaces = 1;
    image_reg.rgpInterfaces = interfaces;

    provider_reg.cAliases = 0;
    provider_reg.rgpszAliases = NULL;
    provider_reg.pUM = &image_reg; // User mode only
    provider_reg.pKM = NULL; // User mode only

    status = BCryptRegisterProvider(ProviderName, CRYPT_OVERWRITE, &provider_reg);
    // ...
    status = BCryptAddContextFunctionProvider(
        CRYPT_LOCAL, NULL, NCRYPT_KEY_STORAGE_INTERFACE,
        NCRYPT_KEY_STORAGE_ALGORITHM, ProviderName,
        CRYPT_PRIORITY_BOTTOM
    );
    // ...
    return status;
}

NTSTATUS WINAPI UnregisterKeyStorageProvider(LPCWSTR ProviderName)
{
    NTSTATUS status;

    status = BCryptRemoveContextFunctionProvider(
        CRYPT_LOCAL, NULL, NCRYPT_KEY_STORAGE_INTERFACE,
        NCRYPT_KEY_STORAGE_ALGORITHM, ProviderName
    );
    // ...
    status = BCryptUnregisterProvider(ProviderName);
    // ...
    return status;
}
```

The screenshot below shows the result. First, a KSP named "foo123" is successfully registered using a non-existent DLL named `foo123.dll`. Then, the program tries to instantiate it, but fails, which is expected since the supporting DLL doesn't exist. However, thanks to Process Monitor, we can see that LSASS tries to load it, which tends to confirm that the KSP registration worked.

![Registering a fake Key Storage Provider named "foo123"](/assets/posts/2024-08-09-ghost-in-the-ppl-part-1/add-ksp-poc-lsass-load-dll.png)
_Registering a fake Key Storage Provider named "foo123"_

My original goal was to load a vulnerable version of `ncryptprov.dll` in LSASS though, so I used this proof-of-concept to register a KSP named "Vulnerable Key Storage Provider" with the path of an older version of this DLL. After that, I used the PoC again to try and open the provider, and it worked! Thanks to [System Informer](https://systeminformer.sourceforge.io/), I could also confirm that the vulnerable DLL was loaded, alongside the original one.

![Loading a vulnerable version of `ncryptprov.dll` in LSASS](/assets/posts/2024-08-09-ghost-in-the-ppl-part-1/poc-load-vulnerable-ksp.png)
_Loading a vulnerable version of `ncryptprov.dll` in LSASS_

After that, I just had to update the exploit code, so that it opens the "Vulnerable Key Storage Provider" instead of the default "Microsoft Software Key Storage Provider", and run it again to confirm that the memory leak worked as intended.

![Testing the information leak exploit again after loading a vulnerable version of `ncryptprov.dll`](/assets/posts/2024-08-09-ghost-in-the-ppl-part-1/poc-address-leak-successful.png)
_Testing the information leak exploit again after loading a vulnerable version of `ncryptprov.dll`_

## Testing the Full Exploit Chain

With the ability to load vulnerable versions of both `keyiso.dll` and `ncryptprov.dll`, it was time to test the full exploit chain. The original PoC uses `LoadLibraryW`, with the absolute path of a DLL on disk. This is perfectly suitable for a privilege escalation scenario where LSASS is not protected. In our case though, this would not work because a PPL won't load a DLL which is not signed by Microsoft. So, I just replaced the address of `LoadLibraryW` with the address of `OutputDebugStringW`, and the DLL path with a custom message. This way, I can see when the execution is triggered using [DebugView](https://learn.microsoft.com/en-us/sysinternals/downloads/debugview), instead of monitoring filesystem events resulting from a call to `LoadLibraryW` with Process Monitor.

After restarting the KeyIso service and registering a custom Key Storage Provider, it was time to run the PoC again. And a few seconds later, I finally saw the message "I'm in LSASS!!!", thus confirming the exploit worked as intended!

![Executing `OutputDebugStringW` from within LSASS](/assets/posts/2024-08-09-ghost-in-the-ppl-part-1/poc-exploit-outputdebugstring-worked.png)
_Executing `OutputDebugStringW` from within LSASS_

## Conclusion

In this first part, we saw that it is possible to use the technique called "Bring Your Own Vulnerable DLL" to reintroduce two vulnerabilities, and then exploit them to gain arbitrary code execution within a protected LSASS process.

![From BYOVDLL to arbitrary code execution within a protected LSASS process](/assets/posts/2024-08-09-ghost-in-the-ppl-part-1/poc-exploit-combined.png)
_From BYOVDLL to arbitrary code execution within a protected LSASS process_

The term "arbitrary" may sound a bit exaggerated at this point though, and rightfully so. We've only proven that we can print a debug message. In the next part, I will go over the exploitation strategies I considered and explored, what failed, and what worked. In the meantime, and if you want to learn more about the OOB read and UAF vulnerabilities, I would suggest that you read the blog post [Isolate me from sandbox - Explore elevation of privilege of CNG Key Isolation](https://whereisk0shl.top/post/isolate-me-from-sandbox-explore-elevation-of-privilege-of-cng-key-isolation).

___This article was originally posted on SCRT's blog [here](https://blog.scrt.ch/2024/08/09/ghost-in-the-ppl-part-1-byovdll/).___