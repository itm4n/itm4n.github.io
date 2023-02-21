---
title: "Revisiting a Credential Guard Bypass" 
layout: "post"
categories: "Windows"
tags: ["Research", "Bypass"]
---

You probably have already heard or read about this clever __Credential Guard__ bypass which consists in simply patching two global variables in LSASS. All the implementations I have found rely on hardcoded offsets, so I wondered how difficult it would be to retrieve these values at run-time instead.


## Background

As a reminder, when (Windows Defender) __Credential Guard__ is enabled on a Windows host, there are two `lsass.exe` processes, the usual one and one running inside a Hyper-V Virtual Machine. Therefore, accessing the juicy stuff in this isolated `lsass.exe` process means breaking the hypervisor, which is not an easy task.

![](/assets/posts/2022-05-23-credential-guard-bypass/00_credential-guard.png)

_Source: [https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-how-it-works](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-how-it-works)_

Though, in August 2020, an article was posted on Team Hydra's blog with the following title: [Bypassing Credential Guard](https://teamhydra.blog/2020/08/25/bypassing-credential-guard/). In this post, [@N4k3dTurtl3](https://twitter.com/N4k3dTurtl3) discussed a very clever and simple trick. In short, the well-known **WDigest** module (`wdigest.dll`), which is loaded by LSASS, has two interesting global variables: `g_IsCredGuardEnabled` and `g_fParameter_UseLogonCredential`. Their name is rather self-explanatory, the first one holds the state of Credential Guard within the module (is it enabled or not?), and the second one determines whether clear-text passwords should be stored in memory. By flipping these two values, you can trick the WDigest module into acting as if Credential Guard was not enabled and if the system was configured to keep clear-text passwords in memory. Once these two values have been properly patched within the LSASS process, the latter will keep a copy of the user's password when the next authentication occurs. In other words, you won't be able to access previously stored credentials but you will be able to extract clear-text passwords afterward.

The implementation of this technique is rather simple. You first determine the offsets of the two global variables by loading `wdigest.dll` in a disassembler or a debugger along with the public symbols (the offsets may vary depending on the file version). After that, you just have to find the module's base address to calculate their absolute addresses. Once their location is known, the values can be patched and/or restored in the target `lsass.exe` process.

The original Proof-of-Concept is available [here](https://gist.github.com/N4kedTurtle/8238f64d18932c7184faa2d0af2f1240). I found two other projects implementing it: [WdToggle](https://github.com/outflanknl/WdToggle) (a BOF module for Cobalt Strike) and [EDRSandblast](https://github.com/wavestone-cdt/EDRSandblast). All these implementations rely on hardcoded offsets, but is there a more elegant way? Is it possible to find them at run-time?

## We need a plan

If we want to find the offsets of these two variables, we first have to understand how and where they are stored. So let's fire up Ghidra, import the file `C:\Windows\System32\wdigest.dll`, load the public symbols and analyze the whole.

Loading the symbols allows us to quickly find these two values from the Symbol Tree. What we learn there is that `g_IsCredGuardEnabled` and `g_fParameter_UseLogonCredential` are two 4-byte values (_i.e._ double words / `DWORD` values) that are stored in the R/W `.data` section, nothing surprising about this.

![](/assets/posts/2022-05-23-credential-guard-bypass/01_ghidra-global-variables.png)

If we take a look at what surrounds these two values, we can see that there is just a bunch of uninitialized data. And even once the module is loaded, there is most probably no particular marker that we will be able to leverage for identifying their location. It is like searching for a needle in a haystack, with the added challenge of not being able to distinguish the needle from the rest of the hay.

![](/assets/posts/2022-05-23-credential-guard-bypass/02_ghidra-uninitialized-data.png)

So, searching directly in the `.data` section is not the way to go. There is a better approach, rather than searching for these values, we can search for cross-references! The reason for these global variables to even exist in the first place is that they are used somewhere in the code. Therefore, if we can find these references, we can also find the variables.

Ghidra conveniently lists all the cross-references in the "Listing" view, so let's see if there is anything of interest.

![](/assets/posts/2022-05-23-credential-guard-bypass/03_ghidra-global-variables-xrefs.png)

Two cross-references immediately stand out - `SpAcceptCredentials` and `SpInitialize` - as they are common to both variables. If we can limit the search to a single place, the whole process will certainly be a bit easier. On top of that, looking at these two functions in the symbol tree, we can see that `SpInitialize` is exported by the DLL, which means that we can easily get its address with a call to `GetProcAddress()` for instance.

![](/assets/posts/2022-05-23-credential-guard-bypass/04_ghidra-common-xrefs.png)

We can go to the "Decompile" view and have a glimpse at how these variables are used within the `SpInitialize` function.

![](/assets/posts/2022-05-23-credential-guard-bypass/05_ghidra-spinitialize-refs.png)

The `RegQueryValueExW` call is interesting because the x86 opcode of a function call is rather easy to identify. From there, we could then work backward and see how the fifth argument is handled. This is a potential avenue to consider so let's keep it in mind.

That would be a way to identify the `g_fParameter_UseLogonCredential` variable but what about `g_IsCredGuardEnabled`? The code from the "Decompile" view is not that easy to interpret as is, so we will have to go a bit deeper.

```cpp
g_IsCredGuardEnabled = (uint)((*(byte *)(param_2 + 1) & 0x20) != 0);
```

Here, I found the assembly code to be less confusing.

```nasm
mov r15,param_2
; ...
test byte ptr [r15 + 0x4],0x20
cmovnz eax,esi
mov dword ptr [g_IsCredGuardEnabled],eax
```

First, the second parameter of the function call - `param_2` - is loaded into the `R15` register. Then, it is incremented by `0x04`, dereferenced and finally compared against the value `0x20`.

The function `Spinitialize` is documented [here](https://docs.microsoft.com/en-us/windows/win32/api/ntsecpkg/nc-ntsecpkg-spinitializefn). The documentation tells us that the second parameter is a pointer to a `SECPKG_PARAMETERS` structure.

```cpp
NTSTATUS Spinitializefn(
  [in] ULONG_PTR PackageId,
  [in] PSECPKG_PARAMETERS Parameters,
  [in] PLSA_SECPKG_FUNCTION_TABLE FunctionTable
)
```

The structure `SECPKG_PARAMETERS` is documented [here](https://docs.microsoft.com/en-us/windows/win32/api/ntsecpkg/ns-ntsecpkg-secpkg_parameters). The attribute located at the offset `0x04` in the structure (_c.f._ `byte ptr [R15 + 0x4]`) is `MachineState`.

```cpp
typedef struct _SECPKG_PARAMETERS {
  ULONG          Version;
  ULONG          MachineState;
  ULONG          SetupMode;
  PSID           DomainSid;
  UNICODE_STRING DomainName;
  UNICODE_STRING DnsDomainName;
  GUID           DomainGuid;
} SECPKG_PARAMETERS, *PSECPKG_PARAMETERS, SECPKG_EVENT_DOMAIN_CHANGE, *PSECPKG_EVENT_DOMAIN_CHANGE;
```

The documentation provides a list of possible flags for the `MachineState` attribute but it does not tell us what flag corresponds to the value `0x20`. However, it does tell us that the `SECPKG_PARAMETERS` structure is defined in the header file `ntsecpkg.h`. If so, we should find it in the Windows SDK, along with the `SECPKG_STATE_*` flags.

```cpp
// Values for MachineState

#define SECPKG_STATE_ENCRYPTION_PERMITTED               0x01
#define SECPKG_STATE_STRONG_ENCRYPTION_PERMITTED        0x02
#define SECPKG_STATE_DOMAIN_CONTROLLER                  0x04
#define SECPKG_STATE_WORKSTATION                        0x08
#define SECPKG_STATE_STANDALONE                         0x10
#define SECPKG_STATE_CRED_ISOLATION_ENABLED             0x20
#define SECPKG_STATE_RESERVED_1                   0x80000000
```

Here we go! The value `0x20` corresponds to the flag `SECPKG_STATE_CRED_ISOLATION_ENABLED`, which makes quite a lot of sense in our case. In the end, the previous line of C code could simply be rewritten as follows.

```cpp
g_IsCredGuardEnabled = (param_2->MachineState & SECPKG_STATE_CRED_ISOLATION_ENABLED) != 0;
```

__Note:__ I could have also helped Ghidra a bit by defining this structure and editing the prototype of the `SpInitialize` function to achieve a similar result.

That's all very well, but do we have clear opcode patterns to search for? The answer is "not really"... Before the `RegQueryValueExW` call, a reference to `g_fParameter_UseLogonCredential` is loaded in `RAX`, that's a rather common operation and we cannot rely on the fact that the compiler will use the same register every time. After the call to `RegQueryValueExW`, `g_fParameter_UseLogonCredential` is set to `0` in an `if` statement. Again this is a generic operation so it is not good enough for establishing a pattern. As for `g_IsCredGuardEnabled`, there is an interesting set of instructions but we cannot rely on the fact that the compiler will produce the same code every time here either.

```nasm
; Before the call to RegQueryValueExW
; 180003180 48 8d 05 2d 30 03 00
lea     rax,[g_fParameter_UseLogonCredential]
; ...
; 18000318e 48 89 44 24 20
mov     qword ptr [rsp + local_b8],rax=>g_fParameter_UseLogonCredential
```

```nasm
; After the call to RegQueryValueExW
; 1800031b1 44 89 25 fc 2f 03 00
mov     dword ptr [g_fParameter_UseLogonCredential],r12d
```

```nasm
; Test on param_2->MachineState
; 18000299b 41 f6 47 04 20
test    byte ptr [r15 + 0x4],0x20
; 1800029a0 0f 45 c6
cmovnz  eax,esi
; 1800029a3 89 05 5f 32 03 00
mov     dword ptr [g_IsCredGuardEnabled],eax
```

We are (almost) back to square one. However, we had a second option - `SpAcceptCredentials` - so let's try our luck with this function. As it turns out, the two variables seem to be used in a single `if` statement as we can see in the "Decompile" view.

![](/assets/posts/2022-05-23-credential-guard-bypass/06_ghidra-spacceptcredentials-decompile.png)

The original assembly consists of a `CMP` instruction, followed by a `MOV` instruction.

```nasm
; 180001839 39 1d 75 49 03 00
cmp     dword ptr [g_fParameter_UseLogonCredential],ebx
; 18000183f 8b 05 c3 43 03 00
mov     eax,dword ptr [g_IsCredGuardEnabled]
; 180001845 0f 85 9c 77 00 00
jnz     LAB_180008fe7
```

Since the public symbols were imported and the PE file was analyzed, Ghidra conveniently displays the references to the variables rather than addresses or offsets. To better understand how this works though, we should have a look at the "raw" assembly code.

```nasm
cmp    dword ptr [rip + 0x34975],ebx  ; 39 1d 75 49 03 00
mov    eax,dword ptr [rip + 0x343c3]  ; 8b 05 c3 43 03 00
jnz    0x77ae                         ; 0f 85 9c 77 00 00
```

On the first line, the first byte - `39` - is the opcode of the `CMP` instruction to compare a 16 or 32-bit register against a 16 or 32-bit value in another register or a memory location. Then, `1d` represents the source register (`EBX` in this case). Finally, `75 49 03 00` is the little-endian representation of the offset of `g_fParameter_UseLogonCredential` relative to `RIP` (`rip+0x34975`). The second line works pretty much the same way although it is a `MOV` instruction.

The third line represents a conditional jump, which won't help us establish a reliable pattern. If we consider only the first two lines though, we can already build a potential pattern: `39 ?? ?? ?? ?? 00 8b ?? ?? ?? ?? 00`. We just make the reasonable assumption that the offsets won't exceed the value `0x00ffffff`.

No need to say that this is not great but there is still room for improvement so let's test it first and see if it is at least good enough as a starting point. For that matter, Ghidra has a convenient "Search Memory" tool that can be used to search for byte patterns.

To my surprise, this simple pattern yielded only one result in the entire file. Of course, it is not completely relevant because the PE file also has uninitialized data that could contain this pattern once it is loaded. Though, to address this issue, we can very well limit the search to the `.text` section because it is not subject to modifications at run-time.

![](/assets/posts/2022-05-23-credential-guard-bypass/07_ghidra-search-memory-pattern.png)

There is still one last problem. I tested the pattern against a single file. What if this pattern is not generic enough or what if it yields false positives in other versions of `wdigest.dll`? If only there was an easy way to get my hands on multiple versions of the file to verify that...

And here comes the [The Windows Binaries Index](https://winbindex.m417z.com/) (or "Winbindex"). This is a nicely designed web application that aggregates all the metadata from update packages released by Microsoft. It also provides a link whenever the file is available for download. Kudos to [@m417z](https://twitter.com/m417z) for this tool, this is a game-changer. From the home page, I can simply search for `wdigest.dll` and virtually get access to any version of the file.

![](/assets/posts/2022-05-23-credential-guard-bypass/08_winbindex-wdigest.png)

Apart from the version installed in my VM (`10.0.19041.388`), I tested the above pattern against the oldest (`10.0.10240.18638` - Windows 10 1507) and the most recent version I could find (`10.0.22000.434` - Windows 11 21H2) and it worked amazingly well in both cases.

It looks like a plan is starting to emerge. In the end, the overall idea is pretty simple. We have to read the DLL, locate the `.text` section and simply search for our pattern in the raw data. From the matching buffer, we will then be able to extract the variable offsets and adjust them (more on that later).

## Practical implementation

Let me quickly recap what we are trying to achieve. We want to read and patch two global variables within the `wdigest.dll` module. Because of their nature, these two variables are located in the R/W `.data` section, but they are not easy to locate as they are just simple boolean flags. However, we identified some code in the `.text` section that references them. So, the idea is to first extract their offsets from the assembly code, and then get the base address of the target module to find their exact location in the `lsass.exe` process.

### Searching for our code pattern

We want to find a portion of the code that matches the pattern `39 ?? ?? ?? ?? 00 8b ?? ?? ?? ?? 00`. To do so, we have to first locate the `.text` section of the `wdigest.dll` PE file. There are two ways to do this. We can either load the module in the memory of our process or read the file from the disk. I decided to go for the second option (for no particular reason).

Locating the `.text` section is easy. The first bytes of the PE file contain the DOS header, which gives us the offset to the NT headers (`e_lfanew`). In the NT headers, we find the `FileHeader` member, which gives us the number of sections (`NumberOfSections`).

```cpp
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    // ...
    LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS;

typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    // ...
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```

We can then simply iterate the section headers that are located after the NT headers until we find the one with the name `.text`.

```cpp
typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    // ...
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    // ...
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

Once we have identified the section header corresponding to the `.text` section, we know its size and offset in the file. With that knowledge, we can invoke `SetFilePointer` to move our pointer of `PointerToRawData` bytes from the beginning of the file and read `SizeOfRawData` bytes into a pre-allocated buffer.

```cpp
// hFile = CreateFileW(L"C:\\Windows\\System32\\wdigest.dll", ...);
PBYTE pTextSection = (PBYTE)LocalAlloc(LPTR, SectionHeader.SizeOfRawData);
SetFilePointer(hFile, SectionHeader.PointerToRawData, NULL, FILE_BEGIN);
ReadFile(hFile, pTextSection, SectionHeader.SizeOfRawData, NULL, NULL);
```

Then, it is just a matter of reading the buffer, which I did with a simple loop. When I find the byte `0x39`, which is the first byte of the pattern, I simply check the following 11 bytes to see if they also match.

```cpp
// Pattern: 39 ?? ?? ?? ?? 00 8b ?? ?? ?? ?? 00
j = 0;
while (j < sh.SizeOfRawData) {
  if (pTextSection[j] == 0x39) {
    if ((pTextSection[j + 5] == 0x00) && (pTextSection[j + 6] == 0x8b) && (pTextSection[j + 11] == 0x00)) {
          wprintf(L"Match at offset: 0x%04x\r\n", SectionHeader.VirtualAddress + j);
    }
  }
}
```

However, I do not stop at the first occurrence. As a simple safeguard, I check the entire section and count the number of times the pattern is matched. If this count is 0, obviously this means that the search failed. But if the count is greater than 1, I also consider that it failed. I want to make sure that the pattern matches only once.

Just for testing purposes and out of curiosity, I also tried several variants of the pattern to sort of see how efficient it was. Surprisingly, the count dropped very quickly with only two occurrences for variant #2.

| Variant | Pattern | Occurrences |
| :---: | :---: | :---: |
| 1 | `39 .. .. .. .. 00 .. .. .. .. .. ..` | 98 |
| 2 | `39 .. .. .. .. 00 8b .. .. .. .. ..` | 2 |
| 3 | `39 .. .. .. .. 00 8b .. .. .. .. 00` | 1 |

If we execute the program, here is what we get so far. We have exactly one match at the offset `0x1839`.

```console
C:\Temp>WDigestCredGuardPatch.exe
Exactly one match found, good to go!
Matched code at 0x00001839: 39 1d 75 49 03 00 8b 05 c3 43 03 00
```

For good measure, we can verify if the offset `0x1839` is correct by going back to Ghidra. And indeed, the code we are interested in starts at `0x180001839`.

![](/assets/posts/2022-05-23-credential-guard-bypass/09_ghidra-pattern-address.png)

__Note:__ the value `0x180000000` is the default base address of the PE. This value can be found in `NtHeaders.OptionalHeader.ImageBase`.

### Extracting the variable offsets

Below are the bytes that we were able to extract from the `.text` section, and their equivalent `x86_64` disassembly.

```nasm
cmp    dword ptr [rip + 0x34975], ebx   ; 39 1D   75 49 03 00
mov    eax, dword ptr [rip + 0x343c3]   ; 8B 05   C3 43 03 00
```

And here is the thing I intentionally glossed over in the first part. Since I am not used to reading assembly code, these two lines initially puzzled me. I was expecting to find the addresses of the two variables directly in the code, but instead, I found only RIP-relative offsets.

I learned that the `x86_64` architecture indeed uses RIP-relative addressing to reference data. As explained in this [post](http://www.nynaeve.net/?p=192), the main advantage of using this kind of addressing is that it produces Position Independent Code (PIC).

The RIP-relative address of `g_fParameter_UseLogonCredential` is `rip+0x34975`. We found the code at the address `0x00001839`, so the _absolute_ offset of `g_fParameter_UseLogonCredential` should be `0x00001839 + 0x34975 = 0x361ae`, right?

![](/assets/posts/2022-05-23-credential-guard-bypass/10_ghidra-uselogoncredential-addr.png)

But the offset is `0x361b4`. Oh, wait... When an instruction is executed, RIP already points to the next one. This means that we must add `6`, the length of the `CMP` instruction, to this value: `0x00001839 + 6 + 0x34975 = 0x361b4`. Here we go!

We apply the same method to the second variable - `g_IsCredGuardEnabled` - and we find: `0x00001839 + 6 + 6 + 0x343c3 = 0x35c08`.

![](/assets/posts/2022-05-23-credential-guard-bypass/11_ghidra-iscredguardenabled-addr.png)

We identified the 12 bytes of code and we know their offset in the PE, so the implementation is pretty easy. The RIP-relative offsets are stored using the little-endian representation, so we can directly copy the four bytes into `DWORD` temporary variables if we want to interpret them as `unsigned long` values.

```cpp
DWORD dwUseLogonCredentialOffset, dwIsCredGuardEnabledOffset;

RtlMoveMemory(&dwUseLogonCredentialOffset, &Code[2], sizeof(dwUseLogonCredentialOffset));
RtlMoveMemory(&dwIsCredGuardEnabledOffset, &Code[8], sizeof(dwIsCredGuardEnabledOffset));
dwUseLogonCredentialOffset += 6 + dwCodeOffset;
dwIsCredGuardEnabledOffset += 6 + 6 + dwCodeOffset;

wprintf(L"Offset of g_fParameter_UseLogonCredential: 0x%08x\r\n", dwUseLogonCredentialOffset);
wprintf(L"Offset of g_IsCredGuardEnabled: 0x%08x\r\n", dwIsCredGuardEnabledOffset);
```

And here is the result.

```console
C:\Temp>WDigestCredGuardPatch.exe
Exactly one match found, good to go!
Matched code at 0x00001839: 39 1d 75 49 03 00 8b 05 c3 43 03 00
Offset of g_fParameter_UseLogonCredential: 0x000361b4
Offset of g_IsCredGuardEnabled: 0x00035c08
```

### Finding the base address

Now that we know the _absolute_ offsets of the two global variables, we must determine their absolute address in the target process `lsass.exe`. Of course, this part was already implemented in the original [PoC](https://gist.github.com/N4kedTurtle/8238f64d18932c7184faa2d0af2f1240), using the following method:

1. Open the `lsass.exe` process with `PROCESS_ALL_ACCESS`.
2. List the loaded modules with `EnumProcessModules`.
3. For each module, call `GetModuleFileNameExA` to determine whether it is `wdigest.dll`.
4. If so, call `GetModuleInformation` to get its base address.

Ideally, we would like to interact as less as possible with LSASS, but as we need to patch it anyway, this method works perfectly fine. I just wanted to take this opportunity to present another approach and discuss some aspects of Windows DLLs.

The key thing is that the base address of a module is determined when it is first loaded. Therefore, any subsequent process loading this module will use the same base address. In our case, this means that if we load `wdigest.dll` in our current process, we will be able to determine its base address without even having to touch LSASS. (I will admit that this sounds a bit dumb because the whole purpose is to eventually patch it.)

Loading a DLL is commonly done through the Windows API `LoadLibraryW` or `LoadLibraryExW`. The documentation states that they return "_a handle to the module_", but I would say that it is a bit misleading. These functions return a `HMODULE`, which is not a typical kernel object `HANDLE`. In reality, the `HMODULE` value is... the base address of the module.

In conclusion, we can get the base address of `wdigest.dll` in the `lsass.exe` process simply by running the following code in our context. One could argue that loading `wdigest.dll` might look suspicious, but it is nothing compared to patching LSASS anyway so this is not my concern here.

```cpp
HMODULE hModule;
if ((hModule = LoadLibraryW(L"wdigest.dll")))
{
  wprintf(L"Base address of wdigest.dll: 0x%016p\r\n", hModule);
  FreeLibrary(hModule);
}
```

After adding this to my own PoC and calculating the addresses, here is what I get. Not bad!

```console
C:\Temp>WDigestCredGuardPatch.exe
Exactly one match found, good to go!
Matched code at 0x00001839: 39 1d 75 49 03 00 8b 05 c3 43 03 00
Offset of g_fParameter_UseLogonCredential: 0x000361b4
Offset of g_IsCredGuardEnabled: 0x00035c08
Base address of wdigest.dll: 0x00007FFEE32B0000
Address of g_fParameter_UseLogonCredential: 0x00007ffee32e61b4
Address of g_IsCredGuardEnabled: 0x00007ffee32e5c08
```

We can confirm that the base address of `wdigest.dll` is the same by inspecting the memory of the `lsass.exe` process using Process Hacker for instance.

![](/assets/posts/2022-05-23-credential-guard-bypass/12_processhacker-lsass-wdigest-address.png)

## Conclusion

The first thing I want to say is thanks to [@N4k3dTurtl3](https://twitter.com/N4k3dTurtl3) for the initial post on this subject. I liked the simplicity and efficiency of this trick. It always amazes me how this kind of hack can defeat advanced protections such as Credential Guard.

Now, the question is, as a pentester (or a red teamer), should you use the technique I described in this post? The idea of not having to rely on hardcoded offsets and therefore running version-independent code is attractive. However, it might also be a bit riskier as pattern matching is not an exact science. To address this, I implemented a safeguard that consists in ensuring that the pattern is matched exactly once. This leaves us with only one potential false positive: the pattern could be matched exactly once on a _random_ portion of code, which seems rather unlikely. The only risk I see is that Microsoft could slightly change the implementation so that my pattern just no longer works.

As for defenders, enabling Credential Guard should not refrain you from enabling LSA protection as well. We all know that it can be completely bypassed, but this operation has a cost for an attacker. It requires running code in the Kernel or using a sophisticated userland bypass, which both create avenues for detection. As rightly said by [@N4k3dTurtl3](https://twitter.com/N4k3dTurtl3):

> _The goal is to increase the cost in time, effort, and tooling [...] thus making your network less appealing as a target and increasing opportunities for detection and response_.

Lastly, this was a cool little challenge, not too difficult, and as always I learned a few things along the way. Oh, and if you have read this far, you can find my Proof-of-Concept [here](https://github.com/itm4n/Pentest-Windows/tree/main/CredGuardBypassOffsets).

## Links & Resources

- Team Hydra - Bypassing Credential Guard  
[https://teamhydra.blog/2020/08/25/bypassing-credential-guard/](https://teamhydra.blog/2020/08/25/bypassing-credential-guard/)
- Winbindex - The Windows Binaries Index  
[https://winbindex.m417z.com/](https://winbindex.m417z.com/)
- Nynaeve - Most data references in x64 are RIP-relative  
[http://www.nynaeve.net/?p=192](http://www.nynaeve.net/?p=192)