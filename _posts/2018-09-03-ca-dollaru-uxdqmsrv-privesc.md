---
title: "CVE-2019-19544 - CA Dollar Universe 5.3.3 'uxdqmsrv' - Privilege Escalation via a Vulnerable SUID Binary"
layout: "post"
categories: "Linux"
tags: ["Research", "Vulnerability", "Privilege Escalation", "Exploit"]
---

A vulnerability was discovered in the `uxdqmsrv` binary. It consists in an arbitrary file write as _root_ that can be leveraged by any local user to gain full _root_ privileges on the host (UNIX/Linux only).

Indeed, the program tries to write to a log file that can be specified using the `U_LOG_FILE` environment variable. When `uxdqmsrv` is owned by _root_ and the `SUID` bit is set (default setup), this file will be created with _root_ privileges if it doesn't exist. Using a UNIX/Linux feature called `umask`, a local user can also control the permissions of the created file and make it world-writable, thus controlling the content of the file.


![](/assets/posts/2018-09-03-ca-dollaru-uxdqmsrv-privesc/ca-dollaru-uxdqmsrv-privesc.gif)

## Vulnerability analysis

On a default UNIX/Linux setup, the binary `uxdqmsrv` is owned by _root_ and is configured with the `SUID` bit. In other words, when executed by a user other than _root_, the system will set the `EUID` to zero so that it can execute code as _root_.

![](/assets/posts/2018-09-03-ca-dollaru-uxdqmsrv-privesc/01_file-permissions.png)

When the program is executed without any arguments, two error messages are displayed. Apparently, it tries to open two files, which cannot be found if the appropriate options are not set.

![](/assets/posts/2018-09-03-ca-dollaru-uxdqmsrv-privesc/02_error-missing-file.png)

The `file` and `ldd` commands will give some basic information about the file. Here, we notice two things:
- Although the host is running a 64-bit OS, the file is a 32-bit executable.
- The file is not _stripped_, i.e. it was compiled with debugging information. This may ease the reverse engineering process.

![](/assets/posts/2018-09-03-ca-dollaru-uxdqmsrv-privesc/03_file-info.png)

Using IDA, we will try to identify the code responsible for the two error messages.
First, we list all the strings that are present in the binary and search for `U_LOG_FILE`. This string is located in the `.rodata` section at the address `0x0806A8FF`. Then, we can list all the references to this address (using `Xrefs to`). In the present case, there is only one reference, so we jump directly to this one.

![](/assets/posts/2018-09-03-ca-dollaru-uxdqmsrv-privesc/04_ida-string-ref.png)

The string `U_LOG_FILE` is indeed used in the instruction at the address `0x08061BCC` (`.text` section).

![](/assets/posts/2018-09-03-ca-dollaru-uxdqmsrv-privesc/05_ida-getenv-call.png)

A pointer to this string is loaded into `EAX`. Then the content of the register is pushed onto the stack and finally `getenv()` is called. This is equivalent to the following C code:

```c
getenv("U_LOG_FILE");
```

This means that the second error message is somehow related to a missing environment variable. So, without further investigation, we can try to set this environment variable and observe the behavior of the program.

As it seems a file is expected, we can try to set the value of the `U_LOG_FILE` variable to a dummy file path. After executing the program, we notice that the second error message has now disappeared.

![](/assets/posts/2018-09-03-ca-dollaru-uxdqmsrv-privesc/06_env-var-and-run.png)

Using `ls`, we can see that the file `foo123.log` was created and is owned by _root_, which means that the program created it without dropping the privileges. However, it can only be modified by _root_, so we get a `Permission denied` error message if we try to modify it.

![](/assets/posts/2018-09-03-ca-dollaru-uxdqmsrv-privesc/07_permission-denied.png)

To work around this issue, we can take advantage of a UNIX/Linux feature, which is called `umask`. `umask` is used to set the default permissions of newly created files. On the screenshot below, we can see that the current `umask` is set to `022`, i.e. new files are created with `rw-r--r--` permissions (and new folders are created with `rwxr-xr-x` permissions).

Therefore, if we set the current `umask` to `0111` (or `0000`, which yields the same result for files), we could theoretically control the permissions of the new file and set them to `rw-rw-rw-`, unless the program sets its own `umask`.

To do so, we use the command `umask 111` (or `umask 000`) and then repeat the previous steps.

![](/assets/posts/2018-09-03-ca-dollaru-uxdqmsrv-privesc/08_using-umask.png)

This time, the file is still owned by _root_ but the permissions are set to `rw-rw-rw-`, which means that we can now modify it.
This arbitrary file creation as _root_ can be used as a primitive to gain full _root_ privileges on the host. This will be explained in the next section.

## Exploit development

When an arbitrary file creation vulnerability is found in a `SUID` binary, a common trick to gain full _root_ privileges is to take advantage of another UNIX/Linux feature: Shared Object preloading.

Shared object preloading can be used to specify libraries that will be loaded by a program before any other library. This can be achieved in two ways: either by setting the `LD_PRELOAD` environment variable or by using the `/etc/ld.so.preload` file, which requires _root_ privileges.

According to the manual, `/etc/ld.so.preload` is a file containing a whitespace-separated list of ELF shared objects to be loaded before the program. Unlike `LD_PRELOAD`, Shared Objects listed in `/etc/ld.so.preload` are loaded even if the program has the `SUID` bit.

![](/assets/posts/2018-09-03-ca-dollaru-uxdqmsrv-privesc/09_man-ld-so-preload.png)

The exploit will consist in using the vulnerable binary to create the `/etc/ld.so.preload` file and using `umask` to make it writable by everyone. This way, we will be able to reference a custom library that will be loaded by any program. Especially, we will use an arbitrary built-in `SUID` binary to trigger the execution of some malicious code as _root_.

As a summary, the following steps will be implemented in the final exploit:

### 1) Create a _root shell_ binary

- It must invoke `setuid(0)` and `setgid(0)` to be able to impersonate _root_.
- It will then call `system('/bin/sh')` to get a shell as _root_.

### 2) Create a custom Shared Object

- We will overwrite the function `geteuid()` (for example).
- The malicious code will set the owner of the _root shell_ binary to _root_, set the `SUID` bit and finally return the result of the legitimate `geteuid()` function.
- The execution of the code will be triggered by a call to `/usr/bin/sudo` (which is also a `SUID` binary owned by _root_).

### 3) Trigger the vulnerability

- Set the `UMASK` to `111` to make new files writable by _everyone_ in the current context.
- Set the environment variable `U_LOG_FILE` to `/etc/ld.so.preload`.
- Execute the vulnerable binary. This way, `/etc/ld.so.preload` will be created and will be writable by the current user.
- Clear the file's content and reference our custom shared object.
- Finally call `/usr/bin/sudo` to trigger the execution of the malicious code.

### 4) Run the _root shell_

- At this stage, the _root shell_ binary should be owned by _root_ and should have the `SUID` and `SGID` bits enabled.
- Running the file should pop a shell as _root_.

## Side note

The machine on which the vulnerability was initially discovered was properly hardened. The `/tmp/` folder was mounted in a separate partition with the option `nosuid`. It means that although the exploit was successful and the _root shell_ was created, it didn't grant _root_ privileges. Therefore, some additional code was added to search for a world-writable directory in `/opt/`. The global variable `USE_TMP` is used in the script to specify whether the exploit should use `/tmp/` as a working directory or recursively search for a suitable one in `/opt/`.

## Remediation

At the time of writing, Dollar Universe 5.3.3 is reaching its end of life. Therefore, no patch has been developped on this version.

However, a workaround exists:
- Remove the `SUID` bit. 
- Create a new entry in `/etc/sudoers` to enable a specific user to run it as _root_. 

Alternatively, upgrade to Dollar Universe 6. 

## Credits

The shared object was taken from the following exploit: [https://www.exploit-db.com/exploits/40768/](https://www.exploit-db.com/exploits/40768/).

## Disclosure timeline

2018-06-06 - Vulnerability discovery  
2018-06-07 - Being redirected to the Product Manager  
2018-06-26 - Report (+demonstration video) sent to vendor  
2018-07-11 - Reminder sent to vendor  
2018-07-12 - Vendor acknowledges vulnerability  
2018-07-12 - Suggested a workaround  
2018-08-02 - Reminder sent to vendor  
2018-08-03 - Workaround accepted by vendor  
2018-08-31 - Vulnerability disclosed  

