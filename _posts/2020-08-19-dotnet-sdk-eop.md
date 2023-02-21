---
title: "Windows .Net Core SDK Elevation of Privilege" 
layout: "post"
categories: "Windows"
tags: ["Research", "Vulnerability", "Privilege Escalation", "Exploit"]
---

There was a weird bug in the __DotNet Core Toolset installer__ that allowed any local user to __elevate their privileges__ to SYSTEM. In this blog post, I want to share the details of this bug that was silently (but only partially) fixed despite not being acknowledged as a vulnerability by Microsoft.


## Introduction

In March 2020, [jonaslyk](https://twitter.com/jonaslyk) told me about a weird bug he encountered on his personal computer. The SYSTEM's `PATH` environment variable was populated with a path that was seemingly related to DotNet. The weird thing was that this path pointed to a non-admin user folder. So, I checked on my own machine but, although there was a DotNet-related path, it pointed to a local admin folder. Anyway, if the path of a user-owned folder can be appended to this environment variable, that means _code execution as SYSTEM_. So, we decided to work together on this strange case and see what we could come up with. 


## The Initial Setup

We started with a clean and fully updated installation of Windows 10. In this initial state, here is the default value of the SYSTEM account's `PATH` environment variable. As a reminder `S-1-5-18` is the Security Identifier (SID) of the `LocalSystem` account.

```batch
reg query "HKU\S-1-5-18\Environment" /v Path
```

![](/assets/posts/2020-08-19-dotnet-sdk-eop/01_path-key-default-value.png)

Then we installed __Visual Studio Community 2019__ ([link](https://visualstudio.microsoft.com/downloads/)). Once installed, we selected the __.Net desktop development__ component in the Installer.

![](/assets/posts/2020-08-19-dotnet-sdk-eop/02_visual-studio-installer.png)

After clicking the "__Install__" button, the packages are downloaded and installed. 

![](/assets/posts/2020-08-19-dotnet-sdk-eop/03_visual-studio-installer-dotnet.png)

We are looking for a registry key modification so we can use __Process Monitor__ to easily monitor what's going on in the background. 

![](/assets/posts/2020-08-19-dotnet-sdk-eop/04_procmon-regsetvalue.png)

Things get interesting when the "__.Net Core toolset__" is installed. We can see a `RegSetValue` operation originating from an executable called `dotnet.exe` on `HKU\.DEFAULT\Environment\PATH`. After this event, we can see that the `PATH` value in  `HKU\S-1-5-18\Environment` is indeed different.

![](/assets/posts/2020-08-19-dotnet-sdk-eop/05_regkey-modification.png)

We may notice two potential issues here:

1. The variable `%USERPROFILE%` is resolved to the current user's home folder instead of the SYSTEM account's home folder.
2. Another path, pointing to a user-owned folder once again, is appended to the the SYSTEM account’s `PATH`.

In these two cases, the current user is a local administrator so the consequences of such modifications are somewhat limited. Though, they shouldn't occur because they may have unintended side effects (e.g.: UAC bypass).

After reading this, you might have a feeling of _déja vu_. If so, it means that you probably stumbled upon this post by [@RedVuln](https://twitter.com/redvuln) at some point: [.Net System Persistence / bypassuac / Privesc](https://redvuln.com/net_privesc/). It looks like he found this bug almost at the same time Jonas and I were working on it. But there is a problem, all of this can be achieved only as an administrator because the installation of the DotNet SDK requires such privileges. Or does it?

## The Actual Privilege Escalation Vulnerability

In the previous part, we saw that the installation process of the .Net SDK had some potentially unintended consequences on the Path Environment variable of the SYSTEM account. Though, strictly speaking, this doesn’t lead to an Elevation of Privilege. 

But, what if I told you that the exact same behavior could be reproduced while being logged in as a normal user with no admin rights?

When Visual Studio is installed, several MSI files seem to be copied to the `C:\Windows\Installer` folder. Since we observed that the `RegSetValue` operation originated from an executable called `dotnet.exe`, we can try to search for this string in these files. Here is what we get using the `findstr` command.

```batch
cd "C:\Windows\Installer"
findstr /I /M "dotnet.exe" "*.msi"
```

![](/assets/posts/2020-08-19-dotnet-sdk-eop/08_findstr-msi-dotnet.png)

Great! We have two matches. What we can do next is try to run each of these files as a normal user with the command `msiexec /qn /a <FILE>` and observe the result on the SYSTEM account’s Environment Path variable in the registry. 

Running the first MSI file, we don’t see anything. However, running the second MSI file, we observe the exact same operation which initially occurred when we installed the DotNet SDK as an administrator.

![](/assets/posts/2020-08-19-dotnet-sdk-eop/07_procmon-poc.png)

This time though, because the MSI file was run by the user `lab-user`, the path `C:\Users\lab-user\.dotnet\tools` is appended to the SYSTEM account's `PATH` environment variable. As a result, this user can now get code execution as SYSTEM by planting a DLL and waiting for a service to load it. This can be achieved - on Windows 10 - by hijacking the `WptsExtensions.dll` DLL which is loaded by the Task Scheduler service upon startup, as described by [@RedVuln](https://twitter.com/RedVuln/) in his post.

## Root Cause Analysis

The exploitation of this bug is trivial so I will focus on the root cause analysis instead, which turned out to be quite interesting for me.

The question is: _where do we start?_ Well, let's start at the beginning... :slightly_smiling_face:

We have a Process Monitor dump file that contains the `RegSetValue` event we are interested in. That's a good starting point. Let's see what we can learn from the Stack Trace.

![](/assets/posts/2020-08-19-dotnet-sdk-eop/10_10_analysis-stack-trace.png)

We can see that the `dotnet.exe` executable loads several DLLs and then loads several .Net assemblies.

![](/assets/posts/2020-08-19-dotnet-sdk-eop/10_11_analysis-dotnet-exe-start.png)

Looking at the details of the `Process Start` operation, we can see the following command line:

```batch
"C:\Program Files\dotnet\\dotnet.exe" exec "C:\Program Files\dotnet\\sdk\3.1.200\dotnet.dll" internal-reportinstallsuccess ""
```

From this command line, we may assume that the Win32 `dotnet.exe` executable is actually a wrapper for the `dotnet.dll` assembly, which is loaded with the following arguments: `internalreportinstallsuccess ""`.

Therefore, reversing this assembly should provide us with all the answers we are looking for:

1. How does the executable evaluate the .Net Core tools path?
2. How does the executable add the path to the SYSTEM account's `PATH` in the registry?

To inspect this assembly, I used [dnSpy](https://github.com/0xd4d/dnSpy). It's definitely the best tool I've used so far for this kind of task.

The Program's `Main` starts by calling `Program.ProcessArgs()`.

![](/assets/posts/2020-08-19-dotnet-sdk-eop/10_12_analysis-dotnet-dll-program-main.png)

Several things happen in this function but the most important part is framed in red on the below screenshot.

![](/assets/posts/2020-08-19-dotnet-sdk-eop/10_13_analysis-dotnet-dll-program-configurefirstuse.png)

Indeed, the function with the name `ConfigureDotNetForFirstTimeUse()` looks like a good candidate to continue the investigation.

![](/assets/posts/2020-08-19-dotnet-sdk-eop/10_14_analysis-dotnet-dll-Program-ConfigureDotNetForFirstTimeUse.png)

This assumption is confirmed when looking at the content of the function because we are starting to see some references to the "Environment Path".

![](/assets/posts/2020-08-19-dotnet-sdk-eop/10_15_analysis-dotnet-dll-ToolsShimPath.png)

The method `CreateEnvironmentPath()` creates an instance of an object implementing the `IEnvironmentProvider` interface, depending on the underlying Operating System. Thus, it would be a new `WindowsEnvironmentPath` object here. 

The object is instantiated based on a dynamically generated path, which is formed by the concatenation of some string and `"tools"`.

![](/assets/posts/2020-08-19-dotnet-sdk-eop/10_16_analysis-dotnet-dll-GetToolsShimPath.png)

This `DotnetUserProfileFolderPath` string itself is the concatenation of some other string and `".dotnet"`.

![](/assets/posts/2020-08-19-dotnet-sdk-eop/10_17_analysis-dotnet-dll-DotnetUserProfileFolderPath.png)

The `DotnetHomePath` string is generated based on the value of an Environment variable.

![](/assets/posts/2020-08-19-dotnet-sdk-eop/10_18_analysis-dll-dotnet-DotnetHomePath.png)

The name of the variable depends on `PlateformHomeVariableName`, which would be `"USERPROFILE"` here because the OS is Windows.

![](/assets/posts/2020-08-19-dotnet-sdk-eop/10_19_analysis-dotnet-dll-PlatformHomeVariableName.png)

To conclude this first part of the analysis, we know that the DotNet tools' path follows the following scheme: `<ENV.USERPROFILE>\.dotnet\tools`, where the value of `ENV.USERPROFILE` is returned by `Environment.GetEnvironmentVariable()`. So far, that's consistent with what we observed with Process Monitor so we must be on the right track.

If we check the documentation of `Environment.GetEnvironmentVariable()`, we can read that, by default, the value is retrieved from the current process if an `EnvironmentVariableTarget` isn’t specified. 

![](/assets/posts/2020-08-19-dotnet-sdk-eop/10_20_doc-GetEnvironmentVariable.png)

Now, if we take another look at the details of the `Process Start` operation in Process Monitor, we can see that the process uses the current user's environment, although it's running as `NT AUTHORITY\SYSTEM`. Therefore, the final tools path is resolved to `C:\Users\lab-user\.dotnet\tools`.

![](/assets/posts/2020-08-19-dotnet-sdk-eop/10_24_analysis-procmon-env-variables.png)

We now know how the path is determined so we have the answer to our first question. We now need to find out how this path is handled afterwards.

To answer the second question, we may go back to the `Program.ConfigureDotNetForFirstTimeUse()` method and see what’s executed after the `CreateEnvironmentPath()` function call.

![](/assets/posts/2020-08-19-dotnet-sdk-eop/10_20_analysis-dotnet-dll-ConfigureDotNetForFirstTimeUse.png)

Once the tools path has been determined, a new `DotnetFirstTimeUseConfigurer` object is created and the `Configure()` method is immediately called. At this point, the path information is stored in the `EnvironmentPath` object identified by the `pathAdder` variable.

In this method, the most relevant piece of code is framed in red on the below screenshot, where the `AddPackageExecutablePath()` method is invoked. 

![](/assets/posts/2020-08-19-dotnet-sdk-eop/10_21_analysis-dotnet-dll-Configure.png)

This method is very simple. The `AddPackageExecutablePathToUserPath()` method is called on the `EnviromentPath` object.

![](/assets/posts/2020-08-19-dotnet-sdk-eop/10_22_analysis-dotnet-dll-AddPackageExecutablePath.png)

The content of the `AddPackageExecutablePathToUserPath()` method finally gives us the answer to our second question.

![](/assets/posts/2020-08-19-dotnet-sdk-eop/10_23_analysis-dotnet-dll-AddPackageExecutablePathToUserPath.png)

First, this method retrieves the value of the `PATH` environment variable but, this time, it uses a slightly different way to do so. It invokes `GetEnvironmentVariable` with an additional `EnvironmentVariableTarget` parameter, which is set to `1`.

From the documentation, we can read that if this parameter is set to `1`, the value is retrieved from the `HKEY_CURRENT_USER\Environment` registry key. The current user being `NT AUTHORITY\SYSTEM` here, the value is retrieved from `HKU\S-1-5-18\Environment`. 

![](/assets/posts/2020-08-19-dotnet-sdk-eop/10_23_analysis-dotnet-dll-AddPackageExecutablePathToUserPath-documentation2.png)

The problem is that this applies to the `SetEnvironmentVariable()` method as well. Therefore, `C:\Users\lab-user\.dotnet\tools\` is appended to the Path Environment variable of the LOCAL SYSTEM account in the registry.

As a conclusion, the .Net Core toolset path is created based on the current user's environment but is applied to the LOCAL SYSTEM account in the registry because the process is running as `NT AUTHORITY\SYSTEM`, hence the vulnerability.

## Conclusion

The status of this vulnerability is quite unclear. Since it wasn't officially acknowledged by Microsoft, there is no CVE ID associated to this finding. Though, as mentioned in the introduction, it has partially been fixed. Namely, the `C:\Users\<USER>\.dotnet\tools` path is no longer appended to the Path if you use one of the latest .NET Core installers. 

__Now, what can you do to make sure your machine isn't affected by this vulnerability?__

First, check the following value in the registry.

```txt
C:\Windows\System32>reg query HKU\S-1-5-18\Environment /v Path

HKEY_USERS\S-1-5-18\Environment
    Path    REG_EXPAND_SZ    %USERPROFILE%\AppData\Local\Microsoft\WindowsApps;
```

If you see something that is different from what is shown above, you may restore the default value using the following command __as an administrator__:

```txt
C:\Windows\System32>reg ADD HKU\S-1-5-18\Environment /v Path /d "%USERPROFILE%\AppData\Local\Microsoft\WindowsApps;" /F
The operation completed successfully.
```

Then, you can update Visual Studio or the .Net SDK and check the registry once again. The "tools" folder should no longer be present.

Unfortunately, according to my latest tests, the `%USERPROFILE%` variable still gets resolved to the current user's "home" folder. This means that the Path is still altered when installing the .Net SDK. Thankfully, this one cannot be exploited for local privilege escalation because the corresponding folder is owned by an administrator.


## Links & Resources

- .Net System Persistence / bypassuac / Privesc  
[https://redvuln.com/net_privesc/](https://redvuln.com/net_privesc/)

- dnSpy  
[dnSpy](https://github.com/0xd4d/dnSpy)

