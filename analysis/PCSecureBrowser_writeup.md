# PCSecureBrowser

So I decided to check out PCSecureBrowser.exe as it was one of few themida protected lockdown browsers. It didn't help with much.

First impression: it's your average evil lockdown browser for exams. Made by ITS, shipped as ClickOnce, version 16.1.14.24, targeting x86 .NET Framework 4.6.2. The shipping binary is Themida packed (lol) and Authenticode signed by ITS (via Sectigo CA). You know, the usual corporate trust chain so your antivirus is like yo whats up my dude instead of evil packed binary.

## What's Inside the Box

The unpacked binary is just a plain WinForms app with a bunch of embedded resources. Once you get rid of the Themida shell, you get the GCO namespace and about 30 C# files. Nothing fancy. No obfuscation beyond Themida on the stub.

Program.cs is the entry point. It shows a splash screen, loads config from params.dat, pulls the Authenticode Description URL from the signed exe via SignInfoConsole.exe, calls SecureConfiguration.FromProcess() on ITS.SbrowserSecurity.dll to set up the security engine, then shows the login form. If the app crashes, it dumps a crashdump.bin via MiniDumpWriteDump. Classic.

SBrowser.cs is the big one. This is where all the managed enforcement lives. It's a WinForms Form that hosts the browser control and runs about 15 different security checks in a timer loop. We'll get into the gory details.

The rest of the cast: MainForm.cs is just the splash screen, WClient.cs is the HTTP client (cert pinning, TLS config, retry logic, WiFi SSID and battery telemetry, because why not), FloatingWindowForm.cs hosts the keyboard hooks and the Alt-Tab replacer, AltTabForm.cs renders DWM thumbnails of allowed windows, ShieldOverlay.cs is the "you can't touch this" overlay that sits under the desktop, BlankForm.cs blacks out secondary monitors, MultiInstanceForm.cs yells at you for running two copies, AuthenticodeTools.cs wraps WinVerifyTrust, CommonUtils.cs does VM/RDP/drive/input-device checks, DeploymentUtils.cs handles ClickOnce detection, NativeMethods.cs holds all the P/Invoke declarations, and SecurityViolation.cs is the enum zoo for violation types.

## The Enforcement Stack

Alright, let's talk about what this thing actually *does* to you. It's all usermode. No kernel driver. No minifilter. Just good old Win32 hooks and process enumeration. Respectable for a lockdown browser, if you actually want to make cheating difficult you'd have some kernel security, but ITS kept it in usermode. Maybe budget constraints, maybe they thought it was enough. Either way, it means every single enforcement mechanism can be bypassed pretty easily.

### Process Detection

The bread and butter. Runs on a timer (every 2 seconds by default) and snapshots the process list via CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), then iterates with Process32First and Process32Next. Simple, reliable, boring.

But the lists themselves are interesting. The blacklist is name-based matching: browsers (chrome.exe, firefox.exe, msedge.exe), screen capture tools (obs64.exe, fraps.exe, bandicam.exe), remote access (teamviewer.exe, anydesk.exe), debuggers (ida.exe, x64dbg.exe, ollydbg.exe), system tools (taskmgr.exe, cmd.exe, powershell.exe), communication apps (zoom.exe, discord.exe, teams.exe). Basically anything that could help you cheat. Then there's a whitelist where only explicitly allowed processes can run, a killlist of processes that get force killed via Process.Kill() with no warning and no mercy, an exitlist of processes that block the exam from starting until you close them, and a user-configurable custom blacklist on top.

All of these lists are server driven. The app downloads them from the server with SecureConfiguration and stores them in memory, so the vendor can update detection at any time without pushing a new binary. Smart design, honestly. The downside is the detection is purely name-based: rename chrome.exe to notepad2.exe and it passes right through. No hash checking, no path validation, no signature verification on detected processes. Just string comparison.

There's also wildcard matching in CommonUtils.IsProcessWildcardMatch, so the server can send patterns like *.exe or chrome*. And a pattern detection system that matches process names against regex-like patterns for things like "any process containing chrome".

### Keyboard Hooking

FloatingWindowForm does the dirty work. It registers two hooks.

The first is WH_KEYBOARD_LL, the low-level keyboard hook via SetWindowsHookEx. The callback checks the pressed key against a list of restricted keys and shortcuts:

```c
// simplified from FloatingWindowForm.KeyboardProcess
switch (vkCode) {
    case VK_LWIN: case VK_RWIN:      // Windows key, obviously
    case VK_SNAPSHOT:                 // PrintScreen, no screenshots for you
    case VK_APPS:                     // context menu key, no right-click menus
        return 1;                     // swallow

    case VK_TAB:                      // Alt+Tab,  classic
        if (altDown) return 1;
        break;
    case VK_F4:                       // Alt+F4, can't quit that way
        if (altDown) return 1;
        break;
    case VK_ESCAPE:                   // Ctrl+Esc opens the Start menu
        if (ctrlDown) return 1;
        break;
    case VK_DELETE:                   // Ctrl+Alt+Del opens the security screen
        if (ctrlDown && altDown) return 1;
        break;
    case VK_F5:                       // refresh, don't want you refreshing the exam
        return 1;
    case VK_LSHIFT + VK_TAB:          // reverse tab, nice try
    case VK_LCONTROL + VK_LSHIFT + VK_Q:  // app-specific kill shortcut,
        return 1;                     // not sure why they block this #ransomware
    }
// plus the entire F1..F12 row, because everyone knows F keys are evil
```

The second is WH_CBT, the computer-based training hook, which monitors window creation and activation events to catch popup dialogs or new windows from blacklisted apps.

On top of that, the callback handles foreground window monitoring via SetWinEventHook(EVENT_SYSTEM_FOREGROUND). Every time a window gains focus it checks whether it's an allowed window, and if not it either blocks it (returns early) or kills the process.

And there's the custom Alt-Tab replacer. When you press Alt+Tab, instead of showing the Windows switcher (which is blocked), the app shows its own AltTabForm, a grid of DWM thumbnails for only the allowed windows, rendered with DwmRegisterThumbnail. Actually kind of slick. Arrow keys, Tab, Enter to switch, Escape to cancel. It's the only way to switch between allowed windows.

### Screen Protection

Two mechanisms here. The first is SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE) on the main browser window, which tells Windows the window should be excluded from screen capture APIs. Any screenshot, screen recording, or screen sharing tool sees a black rectangle where the exam content is.

The second is secondary monitor blanking. BlankForm creates a fullscreen black form on every secondary monitor, positioned via Screen.AllScreens enumeration and SetBounds. The form is TopMost and covers the entire screen, so if you try to drag a window to your second monitor it just disappears behind the black void.

### Screenshot Sanity Check

Since the whole display affinity thing only works if captures of the window come back black, ITS takes exactly one screenshot per session to make sure that's actually happening on your machine. Found it in TestSecurity.dll, and the funny part is BitBlt has exactly one call site in the entire 6 MB DLL:

```c
// IsBlackScreen @ 0x10021e20, reconstructed from disassembly
bool IsBlackScreen() {
    log(1, "IsBlackScreen Check Started");
    HDC screen = GetDC(NULL);                        // whole screen
    HDC mem   = CreateCompatibleDC(screen);
    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);
    HBITMAP bmp = CreateCompatibleBitmap(screen, w, h);
    SelectObject(mem, bmp);
    BitBlt(mem, 0, 0, w, h, screen, 0, 0, SRCCOPY);  // 0xCC0020

    bool all_black = true;
    for (y = 0; y < h; y++)
        for (x = 0; x < w; x++) {
            COLORREF px = GetPixel(mem, x, y);
            if ((px & 0xFF) || ((px >> 8) & 0xFF) || ((px >> 16) & 0xFF)) {
                all_black = false;   // non-black pixel, something is leaking
                goto done;
            }
        }
done:
    log(all_black ? "The screenshot is entirely black"
                  : "The screenshot contains non-black pixels");
    ran_once_flag = 1;               // 0x0d9674b4, one and done
    DeleteObject(bmp); DeleteDC(mem); ReleaseDC(NULL, screen);
    return all_black;
}
```

Those log strings are actually in the binary: "IsBlackScreen Check Started", "The screenshot is entirely black", "The screenshot contains non-black pixels", "IsBlackScreen Check Completed".

The idea is simple. If it screenshots the whole screen and every pixel is black, the exclusion is working on your GPU driver, your monitor setup, whatever RDP weirdness is going on. If any pixel has color in it, either the affinity got bypassed or something is overlaying the exam window, and that gets logged for the server. Runs once per session because of the flag at 0x0d9674b4, and the bitmap is destroyed right after the pixel walk. No WriteFile, no socket, nothing retained. The pixels go absolutely nowhere.

So no, it does not record your screen. The only screenshot this anti cheating software ever takes is to prove that it can't be screenshotted. Poetic, honestly.

### Desktop Shield

ShieldOverlay is a form that positions itself directly under SHELLDLL_DefView (the desktop listview) in the Z-order, using SetParent to make itself a child of the desktop. This blocks any attempts to click on the desktop or interact with desktop icons. The form is transparent (alpha 1) so it doesn't render anything, it's just an invisible wall. Combined with the keyboard hook blocking the Win key, you literally cannot interact with the desktop.

### VM Detection

CommonUtils.DetectVM() is a multi-pronged approach. CPUID leaf 0x40000000 checks the hypervisor vendor string for "VMwareVMware", "VBoxVBoxVBox", "Microsoft Hv", "KVMKVMKVM", "XenVMMXenVMM", "prl hyperv" and "TCGTCGTCGTCG". SMBIOS tables read via GetSystemFirmwareTable('RSMB', 0, ...) get searched for vendor strings like VMware, VirtualBox, QEMU, Xen, innotek, Parallels. WMI queries check Win32_ComputerSystem Manufacturer/Model and Win32_BIOS SerialNumber/Version for VM-specific values. Registry checks hit the usual spots: HKLM\SOFTWARE\VMware, Inc.\VMware Tools, HKLM\SOFTWARE\Oracle\VirtualBox, HKLM\SYSTEM\ControlSet001\Services\vmdebug, and the SCSI DEVICEMAP keys looking for VBOX, VMWARE, QEMU or XEN.

Then MAC address OUIs: the first three bytes of every adapter get compared against 00:0C:29, 00:50:56 and 00:05:69 (VMware), 08:00:27 and 0A:00:27 (VirtualBox), 52:54:00 (QEMU/KVM), 00:16:3E (Xen), 00:1C:42 (Parallels). And finally process-based detection looks for vmtoolsd.exe, vmwaretray.exe, vmwareuser.exe, vboxservice.exe, vboxtray.exe and xenservice.exe.

DetectVMDetailed() returns a structured result with IsVM, a Confidence score from 0 to 100 based on how many indicators matched, VMType, and the list of indicators. Nice API design, honestly.

### RDP Detection

CommonUtils.DetectRDP() checks active network connections on port 3389 via GetExtendedTcpTable, looks for mstsc.exe and rdpclip.exe running, and reads HKLM\SOFTWARE\Microsoft\Terminal Server Client for recent connection traces.

### Input Device Counting

GetRawInputDeviceList() counts mice and keyboards. More than one mouse or more than two keyboards flags as suspicious. Because you know, someone might plug in a second mouse to... cheat? The logic here is questionable but it's a thing they do.

### Clipboard Monitoring

The hook callback intercepts WM_DRAWCLIPBOARD and WM_CHANGECBCHAIN messages. When clipboard changes are detected the app can empty it via OpenClipboard, EmptyClipboard, CloseClipboard. Prevents copy-pasting exam content out.

### Integrity Checks

Several layers. The manifest hash reads gco.app.manifest (an embedded resource), computes SHA1 and compares against a hardcoded salt+hash pair. If the manifest is tampered with the app refuses to run. The salt is hardcoded as GCO$2017!@# in the source. Yeah, that's in plaintext. Real security.

Then a self-version check compares the running assembly's version against what the server expects, with mismatches triggering an update prompt. Authenticode verification uses WinVerifyTrust (via AuthenticodeTools.cs) on loaded plugins and DLLs, with the WINTRUST structures set up as WINTRUST_ACTION_GENERIC_VERIFY_V2 and WTD_CHOICE_FILE. And before launch, the app checks a server endpoint for newer versions; if an upgrade is available it extracts SBU.exe to %TEMP%\OSB\ and launches it elevated via the runas verb.

## The Helper Binaries

This is where it gets fun. The app ships with four embedded resources.

### SBU.exe (Secure Browser Updater)

Native x86 MFC app, version 12.4.0.141, signed by ITS. It's the "Secure Browser Automatic Refresher", a fancy name for an updater. The browser extracts it to %TEMP%\OSB\SBU.exe and launches it elevated with a pile of command-line parameters: /url for the signed download URL, /exe for the browser path to replace, /updateversion and /minversion for version gating, /exitmessage for the failure dialog, /starturl for where to go after the update, /exitstatus for exit code behavior, and /nocheck to skip upgrade checks entirely (useful for testing, or exploitation).

SBU.exe uses WinINet for HTTPS downloads, compares versions via VERSION.dll (VerQueryValue), and replaces the browser executable. It shows a progress dialog during download and relaunches the browser when done. The download URL is signed, but the downloaded payload's Authenticode signature isn't visibly verified by SBU itself. It trusts HTTPS plus the signed URL. Remember that for later.

### SignInfoConsole.exe

Themida-packed .NET console app, version 1.0.0.0. This one is weird. It's a small utility that extracts the deployment configuration from the Authenticode signature of a signed PE file, using the AuthenticodeExaminer library (Kevin Jones' open source project) to parse the PKCS#7 signature blob and pull out the SPC_SP_OPUS_INFO.pMoreInfo URL field.

The thing is, AuthenticodeExaminer.dll isn't shipped on disk and isn't written to disk at runtime. The Themida stub loads it in-memory via Assembly.Load(byte[]) from encrypted storage inside the packer. So you can't just grab it from %TEMP%\OSB, you have to dump process memory and scan for MZ headers with CLR metadata and a valid x86 machine type. That's how I caught it: 64 KB, version 1.0.0.0, fully decompilable once you have the image.

The actual logic is dead simple:

```csharp
// recovered from the dumped image, ~50 lines of real code total
var inspector = new FileInstaller(path);
foreach (var sig in inspector.GetSignatures()) {
    if (sig is AuthenticodeTimestampCmsSignature)
        results.Add(sig.PublisherInformation.UrlLink);
}
Console.WriteLine(string.Join("$$", results));
```

The production output from the main exe's signature is:

```
https://www.starttest.com?agent=WINCSECB&program=162&environment=production&domain=www.programworkshop.com
```

The browser parses this URL to configure itself: which server to talk to, what program ID, what environment. It's the bootstrap config hidden inside the Authenticode signature. Clever, actually. Tamper evident (you'd have to resign the binary) and invisible to casual inspection.

The library itself is well-maintained open source (vcsjones on GitHub). FileInspector opens the PE, reads the security directory entry, loads the PKCS#7 blob and yields ICmsSignature objects. CmsSignatureBase parses the CMS SignerInfo and pulls the SPC_SP_OPUS_INFO attribute from the authenticated attributes. PublisherInformation holds MoreInfo and Description as Uri objects from the SPC_URL_LINK_CHOICE structure. The whole OID chain is SPC_SP_OPUS_INFO_OBJID (1.3.6.1.4.1.311.2.1.12) leading to SPC_URL_LINK_CHOICE, raw URL bytes decoded as UTF-8, parsed as a Uri. That's where ITS stuffs their deployment config.

### TestSecurityCrashHandler.dll

A native DLL for crash dump generation. Called when the app crashes to write a minidump via MiniDumpWriteDump, Breakpad-style, with exports InitBreakpad, SetTestSecurityInstance and SetUserCustomData. It uploads the minidumps itself over WinINet. Presumably phones home to ITS for crash analysis. Bonus: the PDB path leaks a dev username and build layout, C:\Users\tmuthu\Documents\15.6\TestSecurity_Raygun\Release\. Hi tmuthu.

## The Supporting Cast

TestSecurity isn't alone in memory. When the app runs it drags in a whole circus of satellite DLLs that don't ship in the ClickOnce package, they show up at runtime. I dumped everything the process loads and identified all of them.

ITS.SbrowserSecurity.dll is the big one: 188 KB, 75 types, the managed orchestrator. Its SecureConfiguration class is 3,619 lines, because of course it is. It downloads the config XML from the primary domain, fails over to the DR domain with a "ServerProblem" dialog, parses the MultiPublicKeys and PublicKeys blocks (the cert pinning data is server-config driven, not just hardcoded), the AccessibilityProcesses list, and an Update block with CurrentVersion, MinVersion and PackageVersion that drives the SBU.exe upgrade flow. There are also MultiprocessOverlay classes for dealing with WebView2's multi-process window model.

ITS.BrowsersInterface.dll has 144 types, a browser abstraction layer plus a DynamicPluginRouter, which is basically a poor man's DI container that resolves plugin method calls by name at runtime. ITS.Data.dll has 40 types including their own BlowFish.cs implementation. Yes, they wrote their own BlowFish. We'll see why in a second. SecurityJSInterface and SBrowserPluginInterface are two types each, the JS bridge contract and the plugin contract. Mindscape.Raygun4Net4 reports crashes to Raygun (a SaaS), so your exam crashes end up on a dashboard somewhere. Polly does the retry logic. Newtonsoft.Json is there because this project started in 2015 and by god it's going to end there too.

And the browser engine: Edge WebView2 on the Evergreen runtime (Microsoft.Web.WebView2.Core and .WinForms, with an EdgeChromiumTabbedEngine wrapper on top; the native side is EmbeddedBrowserWebView.dll from C:\Program Files (x86)\Microsoft\EdgeWebView\). Not CEF, not IE WebControl. Actual Edge.

So the full stack is: .NET WinForms shell, then ITS.SbrowserSecurity for managed config and orchestration, then TestSecurity.dll for native enforcement, then WebView2 for the actual browser. Layer cake.

## The Native Engine: TestSecurity.dll

I ran the app, dumped everything it loads into memory, and it turns out the .NET layer is just the front desk. The actual stuff that makes it annoying is a native x86 DLL called TestSecurity.dll that the managed wrapper P/Invokes into. 147 exports. A custom .testsec section. Delivered by Themida's in memory loading like the AuthenticodeExaminer trick, only bigger.

Here's what the native layer does that the managed code never mentioned.

IATHookDetection walks the loaded modules of every process it looks at, keeps a seenlist, hashes each module (0x530-byte records), and verifies module paths against the safe list. A module loaded from an unexpected path (read: injected DLL) gets flagged. This is the DLL-injection tripwire. Simplified:

```c
// pseudocode from the decompiled IATHookDetection @ 0x10020410
if (module_seen_before(path)) {
    if (!IsProcessSafeInternal(parent_name) && !IsProcessSafeInternal(module_name))
        log_event(3, "unexpected module in process %s", proc_name);
    return;
}
record_hash_and_store(path, 0x530);          // 1332 byte module record
if (searched_list_has_capacity()) {
    flag_iat_hook_detected = 1;              // _DAT_0d965484 = 1
    return;
}
if (mbsicmp(module_name, "explorer.exe") != 0)   // explorer gets a pass
    log_event(2, "module %s from %s", module_name, module_path);
```

The bypass is path based: your payload needs to live at a whitelisted path, or you need to unhook before it walks you.

Suspend-not-kill is the other big one. PauseResumeThreadList uses CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD) to freeze the *threads* of blacklisted processes instead of terminating them. Server config flags decide the policy: ConfigureDoNotSuspendAppOnInterval, ConfigureWarnOnKillList, and ConfigureSuspendProcessesUsingInternet, which suspends anything using the network. Try pulling up a browser that "isn't on the blacklist" and watch your threads get frozen anyway.

Then there's DetectMiracast, which checks for wireless display sessions because apparently casting your exam to the TV is a thing students try. I went back and disassembled it properly in round two and the whole feature is EnumDisplayDevicesA in a loop, lowercasing the DeviceString and calling strstr against the literal "miracast". One string, one loop, that's the entire export. DetectVirtualMachineByOpm, on the other hand, holds up. It uses the Output Protection Manager API, the same one used for HDCP content protection, to spot display spoofing. That's genuinely creative. I haven't seen that in another proctoring product, and it's the exception that proves the lfind rule.

The toggle surface is DisableWinKey, ConfigureMuteAudio, ConfigureSystemPanel, ConfigureFullScreenMode and friends, all driven by an option bitfield. The import table is also fun: SendInput (the security engine can type for you), NtQueryInformationProcess, WinVerifyTrust, WTSEnumerateProcessesA, DwmGetWindowAttribute, and its own SetWindowsHookExA and SetWinEventHook, so the native layer does its own hooking independent of the C# layer. Two hook layers, one process.

But here's the funny part, and it's the same punchline as everything else in this product: I decompiled IsVirtualMachine, IsRemoteSession and IsUserAdmin in Ghidra, and they're all the same function with different data:

```c
// IsVirtualMachine @ 0x10022210, verbatim from the decompiler
bool IsVirtualMachine(int pid, int nameOverride) {
    char name[260] = {0};
    if (vm_pid_count < 1 && vm_name_count < 1)
        return false;
    if (lfind(&pid, vm_pid_cache, &vm_pid_count, 4, intcmp) != NULL)
        return true;
    if (nameOverride == 0) {
        if (GetRegistryValue(pid, name) == 0)   // WMI/registry name lookup
            return false;
    } else {
        strncpy(name, nameOverride, 0x104);
    }
    return lfind(name, vm_name_cache, &vm_name_count, 0x104, strcmp) != NULL;
}
```

That's it. The "VM detection" in the native engine is lfind against arrays populated from server config at startup. IsRemoteSession and IsUserAdmin are the same three lines pointing at different caches. The OPM trick is the exception, not the rule. The lists ARE the detection. And we have the lists.

A few more gems:

MonitorProcess whitelists "microsoft corporation" by literal string comparison, lowercase, not a signature check:

```c
// MonitorProcess @ 0x10022650, the whitelist check in the middle
name = resolve_process_name(pid);
if (name_is_empty) { log(3, "Failed to get process path for process ( %d & %s )"); return 1; }
ResumeSuspendedProcesses(name, &suspended);
if (name == "microsoft corporation")     // yes, the string, lowercase
    return 1;                             // basically fine, move along
// ... then blacklist / killlist / exitlist lookups against the caches
```

The export named GetProcessHashOfFile has nothing to do with hashing files. It retrieves your active IPv4 address and logs it ("Active IPv4 Address: %s"). Great name, would parse again. RestoreSystem keeps an 0x800-entry ignore list of processes it already restored, because restoring the same process twice would presumably be embarrassing. And the config interval default is 12000 ms, so the security tick runs every 12 seconds unless the encrypted config says otherwise.

### Round Two: Finishing the Exports

The first pass only decompiled 22 of the 147 exports. I went back for the rest, and the native engine got a lot louder.

SecureSystem is not an init function, it's the whole engine. It gates on IsWow64Process (x86 or go home, which, fair, matches the rest of the build), kills stale parent processes left over from the last session, verifies the authority blob pair, and parks itself in a WaitForSingleObject loop ticking on the config interval. The tick body, reconstructed from the disassembly:

```c
// SecureSystem tick, from the disassembly @ rt 0x0d5455a0
save every EdgeUiInputWndClass window on the desktop (max 2048, plus their rects)
fg = GetForegroundWindow();
GetWindowTextA(fg, title); GetClassNameA(fg, cls);
if (fg != my_window && !whitelisted(pid_of(fg))
    && !StrStrIA(title, "Task Switching")
    && !StrStrIA(cls,   "EdgeUiInputTopWndClass")
    && !StrStrIA(title, "DesktopWindowXamlSource")
    && !StrStrIA(title, "Task View")
    && !StrStrIA(title, "XamlExplorerHostIslandWindow")
    && !StrStrIA(title, "WorkerW"))
        record_violation(title, cls);
run blacklist and exitlist pass;
run killlist pass;
if (config says so) SuspendNonAllowedProcessesUsingInternet();
if (GetWindowDisplayAffinity(my_window) == WDA_NONE) {
    SetWindowDisplayAffinity(my_window, WDA_EXCLUDEFROMCAPTURE);   // self healing
    if (++affinity_failures == 3) PostMessageA(my_window, 0x51a, 0, 0);  // three strikes
}
if (config says so) MuteApplication(pid);
MonitorProcess(pid);
restore every EdgeUi window I minimized earlier, via MoveWindow
```

So that's where the shell UI windows keep coming from. Every tick the engine sweeps up the EdgeUiInputWndClass windows, checks the foreground against a hardcoded allowlist of Windows shell titles, and puts everything back at the end. Also notable: the display affinity is not set once at startup the way the managed code implies, it's actively policed on a timer. Something clears it, the engine re-arms it, three failures and it nukes the session via message 0x51a.

The import table hinted at a second keyboard hook and round two confirmed it at function level. The native engine registers its own WH_KEYBOARD_LL proc (WindowsNTKeyboardProc) that tracks Win key state via GetAsyncKeyState on 0x5b and 0x5c, special cases vkCodes 0x100 and 0x104, detects Alt key release, and eats keys by returning 1. So FloatingWindowForm's managed hook is not the only thing swallowing your keystrokes. Two hook layers, one process, and the lower one doesn't show up in any C# decompiler.

The best one: VerifyCertificateSigner is a complete WinVerifyTrust implementation embedded in the DLL, policy GUID and all, with a full error message table sitting in the binary ("The file \"%s\" is not signed.", "The signature is present, but not trusted.", "The signature is present, but specifically disallowed.", the whole CRYPT_E_SECURITY_SETTINGS paragraph). After the trust check it does CryptQueryObject, CertFindCertificateInStore, CertGetNameStringW, and compares the result against the hardcoded string "Internet Testing Systems, LLC".

So the native signature check, the one place in this entire stack that could have used a pinned public key, is a plain string compare against a company name string. They call the strongest verification API Windows offers and then throw away everything it computes except the display name, which they string-compare. The lfind engine even checks signatures.

Smaller round two finds. MuteApplication resolves CLSID_MMDeviceEnumerator and IID_IMMDeviceEnumerator and mutes the default audio endpoint through WASAPI, no per-app session enumeration. CheckMonitorSecurity calls QueryDisplayConfig and posts message 0x51e to the browser window when the display topology ID changes, that's the monitor hotplug tripwire the managed side reacts to. VerifyPhysicalKeyboardPresent queries WMI for win32_keyboard DeviceID, so your exam software now does inventory on your keyboard via CIM. And AddAllowedKey manages a 500 entry, 260 bytes per entry, allowed-key table for the server to populate, dedupe included.

The managed-to-native handshake is also theater. Every registration call carries a random 32-byte authority blob plus its BlowFish encryption under a hardcoded 56-byte key (sb_priv), and the native side verifies the pair:

```csharp
// managed side, ITS.SecurityConfiguration.TestSecurity
public int AddBlacklistProcess(int processId, string processName) {
    byte[] authority = GenerateSecureCode(32);
    byte[] auth      = Encryption.Encrypt(authority, "BlowFish", sb_priv);
    return AddBlacklistProcess(processId, processName,
                               authority, authority.Length,
                               auth, auth.Length);        // native P/Invoke
}
```

Anti-tamper handshake, sure. Except sb_priv is in the binary we decompiled, so anyone can mint valid pairs. It's a speed bump shaped like cryptography.

There's also a second native DLL, ITSEdgeBrowser.dll, still Themida-packed in memory, that combines the same SB_* security API with browser integration (CreateSessionJson, GetDisplayAdapters, SB_GetAppsUsingMediaDevices). 116 exports, list's in the package. Two engines, one job, one of them wearing a Themida hat.

### Config Hiding in the Binary Itself

The native engine also reads BlowFish-encrypted config blobs out of Win32 resources of the host process: IDR_TYPE=101, IDR_URL=117, IDR_ALTURL=124, IDR_INTERVAL=133, IDR_OPTIONS=136. Decrypt with sb_priv, expect an OPTS: or INT: prefix, parse:

```c
// ExtractOptions, simplified from TestSecurity.cs
string hex = ExtractResourceAsString(IDR_OPTIONS, "OPTIONS");
string opts = Encoding.Unicode.GetString(
    Encryption.Decrypt(EncryptionHelper.BytesFromHex(hex), "BlowFish", sb_priv));
if (opts.StartsWith("OPTS:"))
    return Convert.ToInt32(opts.Substring(5));
return 0;
```

The OPTS: blob is a bitfield that becomes the toggle surface: bit 1 task switching allowed, bit 2 VM allowed (skips the VM nag), bit 4 non-admin allowed, bit 8 script activated, 0x10 exit if application not paused, 0x20 exit if blacklist not paused, 0x40 exit on Ctrl+Alt+Del, 0x100 configured logging, 0x800 and 0x1000 clear cache before and after.

So part of the security policy is baked into the binary, encrypted with a key that's in the same binary. The lock and the key live together. Poetic.

## What Was Actually in %TEMP%

Those three anonymous DLLs that get dropped to %TEMP% at startup (391b2e0b.dll and friends, 8.7 KB each)? Not ITS code. The PDB path gives them away: Z:\Development\SecureEngine\src\plugins_manager\internal_plugins\embedded dlls\TlsHelperXBundler\Release\XBundlerTlsHelper.pdb. That's Themida's own TLS helper for the XBundler protection feature. The anticheat ships with its protector's stuff visible on disk. Made me giggle and kick my feet for some reason(sarcastic).

Also worth knowing: of the 183 memory dumps I took during a run, 51 were valid .NET images, and most of the big scary ones were just the CLR materializing framework assemblies (System.Web at 14 MB, System.Windows.Forms at 15 MB) in memory. They look exciting in a dump listing and are 100% boring. Don't waste time on them.

## How This Was All Analyzed

Since the point of writing this up is to save the next person the pain of a Themida binary that downloads components at runtime, here's the recipe.

Embedded resources (SBU.exe, SignInfoConsole.exe, TestSecurityCrashHandler.dll) extract cleanly with Mono.Cecil once you have the unpacked main binary.

Anything Themida loads in memory (AuthenticodeExaminer.dll, TestSecurity.dll, ITSEdgeBrowser.dll) never touches disk. Run the app and poll the process memory for MZ headers with valid PE/CLR metadata, dedupe by hash. Do the same for %TEMP% with a disk watcher, because files get extracted and deleted fast. And mind the self-relaunch: the first process exits and a second one appears, so your watcher needs to track generations by process name, not by PID.

.NET images decompile with ICSharpCode.Decompiler. For the satellite DLLs you need the sibling dumped assemblies on the resolver's search path, or it dies on the first AssemblyRef.

The native TestSecurity.dll dump loads into Ghidra at its preferred base 0x10000000 (memory mapped dump, so RVA equals file offset). pefile chokes on the export table, but parsing the export directory manually is 20 lines of struct.unpack. Internal pointers still reference the original runtime base 0x0d520000, so any string or data address in the decompilation resolves as runtime_addr minus 0x0d520000. That's how you recover every format string and config list location.

Total effort: an afternoon. Themida added maybe 20% overhead, mostly in "why is this DLL not on disk". The answer was always "because it's in memory, go look."

## The Network Layer

WClient.cs is the HTTP client. Some important stuff.

Certificate pinning uses a hardcoded DomainPublicKeys collection checked in the ServicePointManager.ServerCertificateValidationCallback, and the pin list itself is also server-configurable via the config XML's MultiPublicKeys block, so the server can rotate keys without an update.

Config transport is interesting: the config XML comes down AES-encrypted (when encode="2" is set) and gets decrypted on arrival with the hardcoded key in AesCrypto. So the config is encrypted in transit twice (TLS plus AES) and zero times at rest in any meaningful sense.

TLS configuration supports 1.2 and 1.3 via their SecurityProtocolTypeExtensions and SslProtocolsExtensions classes. Retry logic is exponential backoff, well, Polly does it, ITS just calls it.

Telemetry: the client reports WiFi SSID and signal strength (WlanGetAvailableNetworkList), battery status (GetSystemPowerStatus), connected drives, raw input device counts, VM detection results, RDP status, process lists of what's running and what was blocked, screen resolution and monitor count, OS and .NET version, and your active IPv4 address (via the creatively-named GetProcessHashOfFile in the native DLL). All sent as JSON to the server. Because exam proctoring is basically surveillance software, and surveillance software loves telemetry.

Log uploads: security violations are logged locally in %TEMP%\ITSLog\ and uploaded on a timer. The upload URL is built as LogUploadEndPoint?ts=...&environment=...&program-id=...&sbrowser-type=...&institution-id=...&candidate-id=..., then signed with GenerateSecureURL(url, LogUploadSalt) using the hardcoded salt, and each zipped log gets a checksum appended. The signature prevents log tampering, in theory. See: hardcoded salt.

## Le mistakes

BIG BAD PROBLEMAS

JK I'm not trying to help the developers or anything. Figure it out on your own. If I could find them from reversing a themida protected binary, you should be able to with the full source code.

## The Verdict

Look, I'm not going to pretend this is Fort Knox. It's a lockdown browser that does its job in usermode with name based detection and hardcoded secrets. It's effective enough against the average student who doesn't know what a debugger is, but against anyone with basic reverse engineering skills, it's basically a speedbump.

The strengths: themida and some dll injection/hook detection, but %99 of the credit shouldn't go to the actual developers only thing that makes it difficult to bypass is themida.

The weaknesses: x86, like seriously man? Especially with ai nowadays, please convert your codebase to x64 for everyone's sanity.

IMO, for an exam proctoring tool, it's about average. The industry standard is "make it annoying enough that clueless students give up," and that's... well it's a business model, I'll give them that.

But if you were to ask why, it's because not everyone has experience with themida binaries, and I just want to save everyone the hassel of dealing with a themida binary that downloads components at runtime.
They can be very annoying.