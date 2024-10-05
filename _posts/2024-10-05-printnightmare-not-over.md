---
title: "The PrintNightmare is not Over Yet"
layout: "post"
categories: [ "Privilege Escalation" ]
tags: [ "Vulnerability", "Privilege Escalation", "Exploit" ]
---

Following the publication of my blog post [A Practical Guide to PrintNightmare in 2024](/printnightmare-exploitation/), a few people brought to my attention that there was a way to bypass the Point and Print (PnP) restrictions recommended at the end. So, rather than just updating this article with a quick note, I decided to dig a little deeper, and see if I could find a better way to protect against the exploitation of PnP configurations.

## Initial setup

Let's start by laying down the starting conditions, namely the initial Point and Print configuration.

- The policy "__Limits print driver installation to Administrators__" is __disabled__. This change is required, otherwise only administrators can install printer drivers (the default since [KB5005652](https://support.microsoft.com/en-gb/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)), no matter the configuration of other (Package) Point and Print settings.
- The policy "__Only use Package Point and Print__" is __enabled__. Although not strictly required, this policy ensures that we can only install signed package-aware printer drivers.
- The policy "__Package Point and Print - Approved servers__" is __enabled__, and `prt01.foundation.local` is the only authorized print server. This is the most important setting in this scenario.

![Initial Point and Print configuration](/assets/posts/2024-10-05-printnightmare-not-over-yet/gpo-pnp-initial-configuration.png)
_Initial Point and Print configuration_

In these conditions, attempting to install a printer driver from another server, as I explained in my previous post, fails with the error code `0x800704ec`, i.e. `ERROR_ACCESS_DISABLED_BY_POLICY`, as expected.

![Printer driver installation disabled by policy](/assets/posts/2024-10-05-printnightmare-not-over-yet/poc-fail-1-disabledbypolicy.png)
_Printer driver installation disabled by policy_

## The (not so) obvious flaw

In the article [KB5005652](https://support.microsoft.com/en-gb/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872), one can read that "_There is no combination of mitigations that is equivalent to setting RestrictDriverInstallationToAdministrators to 1_". To me, it's a bit like saying "We have restricted the installation of printer drivers to administrators for a reason; you can ignore this warning, but do it at your own risk", without detailing those reasons, or explaining what those risks are.

![Note about the "RestrictDriverInstallationToAdministrators" setting](/assets/posts/2024-10-05-printnightmare-not-over-yet/kb-restrictdriverinstallationtoadministrators.png)
_Note about the "RestrictDriverInstallationToAdministrators" setting_

Nevertheless, I was pretty confident that the "Package Point and print - Approved servers" policy would effectively prevent the abuse of PnP configurations by ensuring that only servers listed in this setting could be used to install printer drivers.

At no point did I consider that this policy could be bypassed simply by spoofing the name of one of the approved servers in the list though. Yet here we are, DNS Spoofing, one of the most elementary network attacks, is all it takes to circumvent this protection.

## DNS spoofing, you said?

To make testing easier in my lab, I didn't set up a custom DNS server. Rather, I added an entry to the `hosts` file of my "victim" domain-joined machine. This entry forces the resolution of `prt01.foundation.local` to the IP address of my malicious print server, instead of the IP address provided by the domain controller.

```plaintext
192.168.177.123    prt01.foundation.local prt01
```

After reproducing the exploit steps described in [the previous post](/printnightmare-exploitation/), and replacing the IP address of the malicious print server with the spoofed name, I still got an error, but with a different status code: `0x80070709`, _i.e._ `ERROR_INVALID_PRINTER_NAME`.

![Printer driver installation failing with the error "invalid printer name"](/assets/posts/2024-10-05-printnightmare-not-over-yet/poc-fail-2-invalidprintername.png)
_Printer driver installation failing with the error "invalid printer name"_

I already had an idea as to what caused this error, but for the sake of demonstration, I chose to debug the issue the _right_ way using Wireshark. Here is what we observe from the standpoint of the malicious print server.

![Analysis of the DCERPC communication between a client and a print server](/assets/posts/2024-10-05-printnightmare-not-over-yet/wireshark-dcerpc-spooler-encrypted.png)
_Analysis of the DCERPC communication between a client and a print server_

The client/server interaction is done entirely over DCE/RPC (at least at this stage), and stops at the `AsyncOpenPrinter` RPC call. However, the dissector only shows encrypted data. Note that this is the result of a patch for [CVE-2021-1678](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1678), which enforces the "Packet Privacy" [RPC authentication level](https://learn.microsoft.com/en-us/windows/win32/rpc/authentication-level-constants) when connecting to the Print Spooler service over the network, to protect against NTLM relay attacks.

> You can read more about this in the article [KB4599464](https://support.microsoft.com/en-us/topic/managing-deployment-of-printer-rpc-binding-changes-for-cve-2021-1678-kb4599464-12a69652-30b9-3d61-d9f7-7201623a8b25) and the security advisory [MSRPC Printer Spooler Relay (CVE-2021-1678)](https://www.crowdstrike.com/blog/cve-2021-1678-printer-spooler-relay-security-advisory/) published by CrowdStrike.
{: .prompt-info }

As explained by Clément Notin ([@cnotin](https://infosec.exchange/@cnotin)) in the blog post [Decrypt Kerberos/NTLM "encrypted stub data" in Wireshark](https://medium.com/tenable-techblog/decrypt-encrypted-stub-data-in-wireshark-deb132c076e7), we can work around this issue by configuring the `NTLMSSP` protocol and set the clear-text NT password used to authenticate against the print server.

![Configuring the NTLM preferences in Wireshark](/assets/posts/2024-10-05-printnightmare-not-over-yet/wireshark-preferences-ntlm-password.png)
_Configuring the NTLM preferences in Wireshark_

As a result, Wireshark is now able to decode NTLM-related data, and thus inspect the content of RPC encrypted stub data. Below is the final result, showing a side-by-side view of the RPC request and response.

![Analysis of an "AsyncOpenPrinter" RPC request with Wireshark](/assets/posts/2024-10-05-printnightmare-not-over-yet/wireshark-dcerpc-spooler-printeropen-error.png)
_Analysis of an "AsyncOpenPrinter" RPC request with Wireshark_

This output is pretty clear. The client wants to open the printer `\\prt01.foundation.local\ACIDDAMAGE`, and our server replies with the error code `0x00000709` ("invalid printer name"). It looks like our (not so) malicious server is a bit too honest about its actual identity. Adding an entry to the `hosts` file with the name of the spoofed server should solve the problem.

After doing that, another printer installation attempt is made, which fails with yet another error code: `0x80070006` (`ERROR_INVALID_HANDLE`). This one was more confusing to me as I could see the printer driver being downloaded from my print server. I even tried to replay the attack using a freshly installed Windows machine, but it failed the same way.

![Installation of a vulnerable printer driver](/assets/posts/2024-10-05-printnightmare-not-over-yet/poc-success-vulnerable-driver-installed.png)
_Installation of a vulnerable printer driver_

Anyway, the printer installation is just a mean to an end. What we really care about is the installation of the vulnerable printer driver. And a quick check with the `Get-PrinterDriver` cmdlet revealed that it was indeed installed. We successfully bypassed the supposedly _secure_ PnP configuration.

## Solution 1: UNC Hardened Access

As we saw earlier, Windows uses DCE/RPC to communicate with the remote print server, but that's not the only communication involved. It also uses SMB to download the driver package through the `print$` share.

![Printer driver package downloaded over SMB](/assets/posts/2024-10-05-printnightmare-not-over-yet/wireshark-smb-driver-file-download.png)
_Printer driver package downloaded over SMB_

So, within an Active Directory environment, one could think that enforcing UNC Path Hardening would be enough to prevent such an attack. Let's take a closer look...

UNC Path Hardening, also called "UNC Hardened Access", was originally added as a security feature to protect against _Man-in-the-Middle_ attacks on the `NETLOGON` and `SYSVOL` shares of domain controllers (see [MS15-011: Vulnerability in Group Policy could allow remote code execution](https://support.microsoft.com/kb/3000483) and [MS15-011 & MS15-014: Hardening Group Policy](https://msrc.microsoft.com/blog/2015/02/ms15-011-ms15-014-hardening-group-policy/)), by enforcing mutual authentication and integrity. This is why Active Directory hardening guides usually recommend setting `\\*\SYSVOL` and `\\*\NETLOGON` as hardened UNC paths (see [here](https://www.stigviewer.com/stig/windows_10/2019-01-04/finding/V-63577)).

The following screenshot shows how the access to the path `\\prt01.foundation.local\*` can be hardened using a GPO deployed on client machines.

![Configuring a hardened UNC path](/assets/posts/2024-10-05-printnightmare-not-over-yet/gpo-hardened-unc-path.png)
_Configuring a hardened UNC path_

After updating the client's group policies, and attempting the attack again, the installation of the printer now fails with the error `0x800704ec`, i.e. `ERROR_ACCESS_DISABLED_BY_POLICY`.

![Printer installation failing because of hardened UNC path](/assets/posts/2024-10-05-printnightmare-not-over-yet/poc-fail-3-disabled-by-policy-hardened-unc.png)
_Printer installation failing because of hardened UNC path_

A quick look at Wireshark confirms that the client fails to establish an SMB session, and immediately closes the connection.

![Client closing the connection to the print server](/assets/posts/2024-10-05-printnightmare-not-over-yet/wireshark-client-closing-printer-session.png)
_Client closing the connection to the print server_

It's a bit too early to claim victory though. To understand why, we need to consider the RPC traffic prior to the download of the printer driver.

![Client requesting the path of the printer driver package](/assets/posts/2024-10-05-printnightmare-not-over-yet/wireshark-rpcgetprinterdriverpackagepath.png)
_Client requesting the path of the printer driver package_

As can be seen on the screenshot above, the client actually retrieves the path of the printer driver package thanks to the RPC procedure `RpcAsyncGetPrinterDriverPackagePath`, which ultimately invokes the internal function `RouterGetPrinterDriverPackagePath`.

![Call tree to "RouterGetPrinterDriverPackagePath"](/assets/posts/2024-10-05-printnightmare-not-over-yet/ghidra-getprinterdriverpackagepath.png)
_Call tree to "RouterGetPrinterDriverPackagePath"_

If this procedure returns the UNC path used by the client to download the package, we should be able to replace it with a local path to bypass the UNC path hardening configuration. To test this theory, I chose to use [Frida](https://frida.re/), and hooked the function `PrvRouterGetPrinterDriverPackagePath`.

> The function `RouterGetPrinterDriverPackagePath` is exported by `spoolsv.exe` with the public symbol `PrvRouterGetPrinterDriverPackagePath`.
{: .prompt-info}

![Inspecting the RPC call used to retrieve the printer driver package path](/assets/posts/2024-10-05-printnightmare-not-over-yet/frida-getprinterdriverpackagepath.png)
_Inspecting the RPC call used to retrieve the printer driver package path_

Unsurprisingly, this function indeed returned the UNC path of the printer driver package on the `print$` share. So, next, I copied the CAB file to the target machine, and used the following Frida script to replace the UNC path returned by the print server with the local path of this file.

```javascript
var pszDriverPackageCab
var cchDriverPackageCab
const fakePackagePath = "C:\\Test\\lmud1o40.inf_amd64_b2faa2ece3fcef36.cab"
var PrvRouterGetPrinterDriverPackagePath = Module.findExportByName("spoolsv.exe", "PrvRouterGetPrinterDriverPackagePath")

Interceptor.attach(PrvRouterGetPrinterDriverPackagePath, {
    onEnter: function (args) {
        pszDriverPackageCab = args[4]
        cchDriverPackageCab = args[5]
    },
    onLeave: function (result) {
        if (cchDriverPackageCab.toInt32() !== 0) {
            // We should check the buffer size, but that's ok for the poc.
            console.log("\nWriting new printer driver package path...")
            pszDriverPackageCab.writeUtf16String(fakePackagePath)
        }
    }
});
```

And it worked! Despite the error code `0x80070006` we saw earlier, the printer driver was yet again successfully installed!

![Vulnerable printer driver installed from a local CAB file](/assets/posts/2024-10-05-printnightmare-not-over-yet/poc-success-unc-hardening-bypass.png)
_Vulnerable printer driver installed from a local CAB file_

In conclusion, UNC Hardened Access is not sufficient on its own to protect against a _Man-in-the-Middle_ attack in this scenario.

## Solution 2: RPC over named pipe + UNC Hardened Access

A Windows print server ~~can~~ could be accessed using RPC over TCP and RPC over SMB (through a named pipe). In a recent update, though, Microsoft [announced](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print) that this would change starting from Windows 11 22H2.

As a result of this update, using RPC over Named Pipes (_i.e._ over SMB) is still available, but disabled by default. Therefore, the spooler only listens for incoming connections via RPC over TCP, and the named pipe `spoolss` isn't available.

I don't know what motivated this change, but that's unfortunate, because my next idea for protecting the spooler against _Man-in-the-Middle_ attacks was to enforce RPC over SMB, in addition to the previous UNC Hardened Access. However, this update also brings new settings to configure and modify this default behavior, so let's test that out.

Most notably, we can configure the policy "RPC connection settings" and select "RPC over named pipes" as the protocol to use for outgoing RPC connections.

> My domain controller is currently running Windows Server 2022 21H2, so the new Administrative Templates were not available. I had to download and install the latest available from this [link](https://www.microsoft.com/en-us/download/details.aspx?id=105667).
{: .prompt-info}

![Configuring RPC connection settings](/assets/posts/2024-10-05-printnightmare-not-over-yet/gpo-rpc-connection-settings.png)
_Configuring RPC connection settings_

Since my attacking machine is running Windows 11 23H2, it is affected by the change, and therefore my print spooler only expects connections via RPC over TCP. To reenable RPC connections over SMB, we can either configure local group policies, or use the following commands.

```batch
REM RPC over named pipes = 0x03
REM RPC over TCP = 0x05
REM RPC over named pipes and TCP = 0x07
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" /v "RpcProtocols" /t REG_DWORD /d 0x7 /f
REM Restart the Print Spooler service
net stop spooler
net start spooler
REM Check whether the named pipe 'spoolss' exists
powershell "[IO.File]::GetAttributes('\\.\pipe\spoolss')"
```

And, it didn't work. More precisely, it didn't work the way I expected. The client machine did try to communicate using RPC over SMB, and since UNC path hardening was configured, this failed, which was the expected behavior. But then, it fell back to RPC over TCP, thus rendering the policy completely useless, at least for what I had in mind.

![Fallback from RPC over SMB to RPC over TCP](/assets/posts/2024-10-05-printnightmare-not-over-yet/wireshark-dcerpc-fallback.png)
_Fallback from RPC over SMB to RPC over TCP_

## Solution 3: Print Driver exclusion list

If you read the title, and thought "it sounds like a bad idea", you are completely right, but I wanted to mention it quickly.

While browsing through the existing policies related to printers, I found this one. I would have preferred something like an "allow list", rather than a "block list", but it's better than nothing I guess.

![Print driver exclusion list policy](/assets/posts/2024-10-05-printnightmare-not-over-yet/gpo-print-driver-exclusion-list.png)
_Print driver exclusion list policy_

So, I read the description and saw this: "_Entries in the exclusion list consist of a SHA256 hash [...] of the INF file and/or main driver DLL file of the driver and the name of the file_". 

Although this description looked horrendous from a security perspective, I gave it a try anyway. I added the SHA256 hash of both `LMUD1o40.inf` and `UNIDRV.DLL` to the exclusion list, and it didn't work. It didn't prevent the installation of the vulnerable printer driver.

![Print driver exclusion list policy configured](/assets/posts/2024-10-05-printnightmare-not-over-yet/gpo-print-driver-exclusion-list-configured.png)
_Print driver exclusion list policy configured_

I don't know what I did wrong. The description does mention a "file hash", not an Authenticode thumbprint. So, it shows that this policy is error-prone, on top of being useless from a security perspective, because one can easily modify a file such that its hash changes without invalidating its Authenticode signature, if it's a signed executable. Nevertheless, I don't think this policy was ever intended for security purposes. Rather, it was probably meant to provide a way to block incompatible drivers.

And, obviously, even if this policy was intended as a security feature, it is flawed by design since it is based on a "block list", rather than an "allow list". So, in the same vein as [known vulnerable kernel drivers](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules), you would have to maintain this list, rather than just allowing the ones you are using, which seems a lot more manageable with printer drivers than with typical kernel drivers.

## Conclusion

That's it for this update. I have to admit I'm running out of ideas, and I see no added value in spending more time searching for potentially hazardous configurations that might provide a false sense of security.

The key takeaway is that the seemingly innocuous statement "_There is no combination of mitigations that is equivalent to setting Restrict Driver Installation To Administrators to 1_" in the Microsoft KB article [KB5005652 - Manage new Point and Print default driver installation behavior (CVE-2021-34481)](https://support.microsoft.com/en-gb/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872) should actually be considered literally. Indeed, you can't secure a Point and Print configuration if you allow low-privileged users to install printer drivers in one way or another.

I'm curious to see if, and how, the new Windows Protected Print (WPP) mode, [announced by Microsoft](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/a-new-modern-and-secure-print-experience-from-windows/ba-p/4002645) last December will address this issue once it gets adopted at a large scale. In the meantime, system administrators should make sure they do not disable the new printer driver restrictions which aim at protecting against CVE-2021-34481. Although it might be a daunting task for some organizations, it seems that the safest way to manage legacy printers is to pre-install their driver packages on client workstations, or deploy them using GPOs and install scripts, if need be.

Last but not least, I want to thank [@parzel](https://chaos.social/@parzel), working with [modzero](https://modzero.com/), and [@laxa](https://x.com/l4x4), working with [Synacktiv](https://www.synacktiv.com/), who both brought this bypass to my attention, only a few weeks apart, and participated in the brainstorming process to help find and explore alternative mitigation. Big props to them!