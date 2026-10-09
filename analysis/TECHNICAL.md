# PCSecureBrowser Technical Reference

## 0. Product

ITS PCSecureBrowser 16.1.14.24, x86, .NET Framework 4.6.2, WinForms, ClickOnce. Protector: Themida. Signing: Authenticode (Sectigo).

## 1. Process layout

```
PCSecureBrowser.exe            managed orchestrator, Themida-packed on disk
 ├─ TestSecurity.dll           native x86 enforcement engine, 147 exports, in-memory load
 ├─ ITSEdgeBrowser.dll         native browser+security bridge, 116 exports, Themida-packed in memory
 ├─ WebView2Loader.dll         browser engine host
 │   └─ msedgewebview2.exe    Edge WebView2 (Evergreen runtime)
 ├─ ITS.SbrowserSecurity.dll   managed config/security orchestrator, in-memory load
 ├─ ITS.BrowsersInterface.dll  engine abstraction (EdgeChromiumTabbedEngine)
 ├─ ITS.Data.dll               persistence
 ├─ SBU.exe                    updater, native x86 MFC, extracted to %TEMP%\OSB
 ├─ SignInfoConsole.exe        Authenticode metadata parser, .NET, extracted to %TEMP%\OSB
 │   └─ AuthenticodeExaminer.dll  in-memory Assembly.Load(byte[]), never on disk
 └─ TestSecurityCrashHandler.dll  Breakpad-based crash handler
```

## 2. Bootstrap

```c
Program.Main() {
    Application.EnableVisualStyles();
    if (Debugger.IsAttached) config.environment = QA;
    splash = new MainForm();
    params = AesDecrypt(File.ReadAllBytes("params.dat"));        // AES-256-CBC, zero IV, hardcoded key
    deployUrl = RunSignInfoConsole(typeof(Program).Assembly.Location);   // reads SPC_SP_OPUS_INFO.pMoreInfo
    opts = ParseDeployUrl(deployUrl);                            // agent, program, environment, domain
    secureConfig = SecureConfiguration.FromProcess(opts);        // loads TestSecurity.dll, downloads config
    Application.Run(new SBrowser(secureConfig));
}
```

```c
ParseDeployUrl(url) {
    u = new Uri(url);
    return { agent: u.Query["agent"],             // WINCSECB
             program: u.Query["program"],         // 162
             environment: u.Query["environment"],
             domain: u.Query["domain"] };         // www.programworkshop.com (DR)
}
```

## 3. Managed security orchestrator (ITS.SbrowserSecurity)

```c
SecureConfiguration.FromProcess(opts) {
    DownloadConfig(opts.domain, "/path");                        // WClient, pinned TLS
    xml = AesCrypto.Decrypt(response, KEY, IV=0);
    ParseLists(xml);                                             // blacklist, safe, killlist, exitlist, accessibility
    ExtractOptions(resourceBlob);                                // BlowFish "OPTS:" blob, key sb_priv
    ExtractInterval(resourceBlob);                               // BlowFish "INT:" blob
    native = LoadLibrary("TestSecurity.dll");                    // P/Invoke SB_* surface
    SB_SecureSystem(authority, BlowFish(authority, sb_priv));    // handshake: random blob + its encryption
}
```

Config download with failover:

```c
DownloadConfig(primary, dr) {
    r = TryGet(primary);                                         // www.starttest.com
    if (r.failed) r = TryGet(dr);
    return r;
}
```

Managed→native call pattern:

```c
AddBlacklistProcess(name) {
    authority = Random(32);
    auth = BlowFishEncrypt(authority, sb_priv);
    SB_AddBlacklistProcess(authority, auth, name);
}
```

## 4. Native engine (TestSecurity.dll)

Option bitfield from `OPTS:` blob drives SB_Configure* exports. Violation decision per tick:

```c
MonitorProcess(pid) {
    name = ResolveImageName(pid);                                // GetModuleFileNameExA fallback
    ResumeSuspendedProcesses(name);
    if (StrStrIA(name, "microsoft corporation")) return;         // whitelist by name substring
    if (InKillList(name))       action = KILL;
    else if (InBlacklist(name)) action = SUSPEND_OR_WARN;        // policy from option bits
    else if (InExitList(name))  action = EXIT_EXAM;
    else if (IsVMProcess(name)) action = VIOLATION_VM;
    RaiseEvent(action);
}
```

SecureSystem main loop (worker thread, 0x114c-byte frame):

```c
SecureSystem(hEvent, auth, authLen, ack, ackLen, pid) {
    if (!IsWow64Process(GetCurrentProcess(), &wow64) || !wow64) return 0;
    KillStaleProcessesFromLastSession();
    if (!authority || !ack || authLen != ackLen) return 0;
    if (!VerifyAuthorityPair(auth, ack)) return 0;
    buf = GlobalAlloc(GMEM_FIXED, 0x2040);
    memcpy(buf, auth, authLen);
    g_state = buf;
    while (WaitForSingleObject(hEvent, interval) == WAIT_TIMEOUT) {
        KillParentProcessesNotOnList(pid);                       // pid array @0x0d626e18
        RestoreSystem(ignore_list);
        Tick();                                                  // body below
    }
}
```

Security tick (inside SecureSystem loop, reimplemented from disassembly):

```c
Tick() {
    hwnds[2048];
    for (w = FindWindowExA(GetDesktopWindow(), 0, "EdgeUiInputWndClass", 0);
         w && count < 2048; w = FindWindowExA(0, w, "EdgeUiInputWndClass", 0)) {
        hwnds[count++] = w;
        GetWindowRect(w, &rects[count-1]);                       // 16-byte rect records
    }
    start = GetTickCount();
    do {
        fg = GetForegroundWindow();
        GetWindowTextA(fg, title, 260); GetClassNameA(fg, cls, 260);
        if (fg != g_sbWindow && !IsProcessWhitelisted(pidOf(fg))
            && !StrStrIA(title, "Task Switching")
            && !StrStrIA(cls,   "EdgeUiInputTopWndClass")
            && !StrStrIA(title, "DesktopWindowXamlSource")
            && !StrStrIA(title, "Task View")
            && !StrStrIA(title, "XamlExplorerHostIslandWindow")
            && !StrStrIA(title, "WorkerW"))
            AddViolationRecord(title, cls);
        if (Elapsed(start) >= min(interval, 2000)) break;
    } while (WaitForSingleObject(hEvent, 0) == WAIT_TIMEOUT);
    if (monitorConfigChanged) PostMessageA(g_sbWindow, 0x51e, topology, 0);
    if (g_flags.a) RestoreSystem();
    if (g_flags.b && g_flags.c) f_0d5481c0();
    BlackListAndExitList(pid);
    KillList(pid);
    if (opt.suspendInternet) SuspendNonAllowedProcessesUsingInternet();
    if (opt.exitIfCtrlAltDel && g_keyState && !g_suppress) {
        if (!IsBlackScreenFlag()) {
            GetWindowDisplayAffinity(g_sbWindow, &aff);
            if (aff == WDA_NONE) {
                SetWindowDisplayAffinity(g_sbWindow, WDA_EXCLUDEFROMCAPTURE);
                if (++rearmCount == 3) PostMessageA(g_sbWindow, 0x51a, 0, 0);
            }
        }
    }
    if (opt.muteAudio) MuteApplication(g_mutePid);
    MonitorProcess(g_monitoredPid);
    for (i = 0; i < count; i++)                                 // restore EdgeUi windows
        MoveWindow(hwnds[i], rects[i].left, rects[i].top,
                   rects[i].right - rects[i].left, rects[i].bottom - rects[i].top, TRUE);
}
```

Native keyboard hook (WindowsNTKeyboardProc, WH_KEYBOARD_LL):

```c
KeyboardProc(nCode, wParam, lParam) {
    k = (KBDLLHOOKSTRUCT*)lParam;
    if (nCode < 0 || nCode != HC_ACTION) return CallNextHookEx(hHook, nCode, wParam, lParam);
    if (GetAsyncKeyState(0x5b) & 1 || GetAsyncKeyState(0x5c) & 1) g_winKeyPressed = 1;
    if (nCode == 0 && (k.vkCode == 0x100 || k.vkCode == 0x104)) {
        ToUnicodeStateScan(k);                                    // helper 0x0d536c60
        suppress = (k.vkCode == 0x100 || k.vkCode == 0x104);
        if (g_altState && k.flags == LLKHF_UP /*8*/) g_keyState = 1;
        TranslateAndForward(k, suppress);                         // helper 0x0d53edb0
        if (suppress) return 1;                                   // eat VK 0x100/0x104 (Win key pair)
        ConvertVkToWM(k, &g_winKeyPressed);                       // helper 0x0d53cbf0
        if (translated) return 1;
    }
    return CallNextHookEx(hHook, nCode, wParam, lParam);
}
```

Authenticode verification (VerifyCertificateSigner):

```c
VerifyCertificateSigner(path) {
    static expectedSigner = "Internet Testing Systems, LLC";
    policy = { 00AAC56B-CD44-11D0-8CC2-00C04FC295EE };            // WINTRUST_ACTION_GENERIC_VERIFY_V2
    error = WinVerifyTrust(INVALID_HANDLE_VALUE, &policy, &WINTRUST_DATA{WTD_CHOICE_FILE, path});
    switch (error) {
        case TRUST_E_NOSIGNATURE:      Log("The file \"%s\" is not signed.");            return false;
        case TRUST_E_PROVIDER_UNKNOWN: Log("The signature is present, but not trusted.");  return false;
        case TRUST_E_SUBJECT_NOT_TRUSTED: GetLastError();                                  return false;
        case TRUST_E_EXPLICIT_DISTRUST:   Log("signature specifically disallowed.");       return false;
        case CRYPT_E_SECURITY_SETTINGS:   Log("CRYPT_E_SECURITY_SETTINGS ...");            return false;
        case 0: Log("The file \"%s\" is signed and the signature was verified."); break;
        default: Log("An unknown error occurred ... Error is: 0x%x");                      return false;
    }
    CryptQueryObject(CERT_QUERY_OBJECT_FILE, path, CERT_QUERY_CONTENT_FLAG_PKCS_SIGNED_EMBED,
                     CERT_QUERY_FORMAT_FLAG_BINARY, 0, 0, 0, 0, &store, &msg, NULL);
    cert = CertFindCertificateInStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                                      CERT_FIND_ANY, NULL, NULL);
    n = CertGetNameStringA(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
    name = Alloc(n * 2);
    CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, name, n);
    return wcscmp(name, expectedSigner) == 0;
}
```

Monitor topology check (CheckMonitorSecurity):

```c
CheckMonitorSecurity() {
    hmon = MonitorFromWindow(GetDesktopWindow(), MONITOR_DEFAULTTOPRIMARY);
    GetPhysicalMonitorsFromHMONITOR(hmon, 1, &mon);
    GetDisplayConfigBufferSizes(QDC_ONLY_ACTIVE_PATHS, &nPaths, &nModes);
    paths = Alloc(nPaths * 32); modes = Alloc(nModes * 72);
    QueryDisplayConfig(QDC_ONLY_ACTIVE_PATHS, &nPaths, paths, &nModes, modes, &topologyId);
    if ((nPaths == 2 && (topologyId == 2 || topologyId == 3 || sourceCount > 1))
        || ((nPaths == 4 || nPaths == 8) && topologyId == 3)) {
        g_topologyFlag = 1;
        PostMessageA(g_sbWindow, 0x51e, topologyId, 0);           // config-change signal
    }
}
```

Miracast / virtual display detection:

```c
DetectMiracast() {
    for (i = 0; EnumDisplayDevicesA(NULL, i, &dd, 0); i++)
        if (strstr(lowercase(dd.DeviceString), "miracast")) return 1;
    return 0;
}
```

Audio muting (MuteApplication):

```c
MuteApplication(pid) {
    CoInitialize(NULL);
    CoCreateInstance(CLSID_MMDeviceEnumerator,                    // {BCDE0395-E52F-467C-8E3D-C4579291692E}
                     NULL, CLSCTX_ALL, IID_IMMDeviceEnumerator,   // {A95664D2-9614-4F35-A746-DE8DB63617E6}
                     &enumerator);
    dev = enumerator.GetDefaultAudioEndpoint(eRender, eMultimedia);
    vol = dev.Activate(ISimpleAudioVolume);
    if (!IsProcessWhitelisted(pid) && !IsProcessHideWhiteListed(pid))
        vol.SetMute(TRUE, NULL);
}
```

WMI access (GetWMIProperty):

```c
GetWMIProperty(objPath, prop) {
    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    CoInitializeSecurity(-1, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE);
    CoCreateInstance(CLSID_WbemLocator, IID_IWbemLocator, &loc);
    loc.ConnectServer(L"ROOT\\CIMV2", L"win32_keyboard", ...);    // callers pass class + property (DeviceID)
    CoSetProxyBlanket(svc, ...);
    exec and read property;
}
```

Allowed-key list (AddAllowedKey):

```c
AddAllowedKey(name, remove) {
    if (!name) return;
    if (!remove) {
        if (FindInTable(name, keys, keyCount, 260)) return;       // dedupe
        if (keyCount >= 500) return;
        strcpy(keys[keyCount++], name);                           // table @0x0d63b040
    } else {
        RemoveFromTable(name, keys, &keyCount, 260);
    }
}
```

List membership core:

```c
IsVirtualMachine(pid, name) {
    if (lfind(&pid, vm_pid_cache, &vm_pid_count, 4, intcmp)) return true;
    if (!name) name = GetRegistryValue(pid);                     // WMI-resolved image name
    return lfind(name, vm_name_cache, &vm_name_count, 0x104, strcmp) != NULL;
}
```

Same body for IsRemoteSession (caches 0x0dacebb0/0x0dacf380) and IsUserAdmin (0x0da8e458/0x0da8ec28).

IAT hook / injected module tripwire:

```c
IATHookDetection(process) {
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process.pid);
    for (m in Module32First/Next(snap)) {
        path = GetModuleFileNameExA(process.h, m.hModule);
        if (!SeenBefore(path, seen_list /*0x530-byte records*/)) {
            Log("module first sight");
            StoreRecord(hash(path), path);
        }
        if (!IsPathInSafeList(path)) {                           // mbsicmp path + basename
            flag = 1;                                            // _DAT_0d965484
            Log("untrusted module path");
        }
    }
}
```

Thread suspension:

```c
PauseResumeThreadList(name, suspend) {
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    for (t in Thread32First/Next(snap)) {
        pid = th32OwnerProcessID;
        if (MatchList(pid)) {
            h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, t.th32ThreadID);
            suspend ? SuspendThread(h) : ResumeThread(h);
            CloseHandle(h);
        }
    }
}
```

Display-affinity self-test (runs once per session, flag 0x0d9674b4):

```c
IsBlackScreen() {
    Log("IsBlackScreen Check Started");
    screen = GetDC(NULL);
    mem = CreateCompatibleDC(screen);
    w = GetSystemMetrics(SM_CXSCREEN); h = GetSystemMetrics(SM_CYSCREEN);
    bmp = CreateCompatibleBitmap(screen, w, h);
    SelectObject(mem, bmp);
    BitBlt(mem, 0, 0, w, h, screen, 0, 0, SRCCOPY);
    for (y = 0; y < h; y++)
        for (x = 0; x < w; x++) {
            p = GetPixel(mem, x, y);
            if ((p & 0xFF) || ((p >> 8) & 0xFF) || ((p >> 16) & 0xFF))
                { all_black = false; goto done; }
        }
done:
    Log(all_black ? "The screenshot is entirely black"
                  : "The screenshot contains non-black pixels");
    DeleteObject(bmp); DeleteDC(mem); ReleaseDC(NULL, screen);
    return all_black;
}
```

OPM display-spoof check:

```c
DetectVirtualMachineByOpm() {
    hdc = GetDC(NULL);
    EnumDisplayMonitors(hdc, NULL, cb, 0);                       // per HMONITOR
    GetPhysicalMonitorsFromHMONITOR(hmon, count, monitors);
    GetMonitorCapabilities(monitors[i].hPhysicalMonitor, &caps, &temps);
    if (!(caps & MC_CAPS_DISPLAY_ADJUSTMENT) || OPMOutputFails())
        return VIOLATION;
}
```

Restore path:

```c
RestoreSystem() {
    for (name in restored_ignore_list /*0x800 entries*/)          // dedupe cache
        UndoHooksAndWindows(name);
}
```

## 5. Input control (FloatingWindowForm)

```c
Install() {
    kbHook = SetWindowsHookExW(WH_KEYBOARD_LL /*13*/, KeyboardProc, hMod, 0);
    cbtHook = SetWindowsHookExW(WH_CBT /*5*/, CbtProc, hMod, 0);
    SetWinEventHook(EVENT_SYSTEM_FOREGROUND /*0x0003*/, EVENT_SYSTEM_FOREGROUND, hMod, ForegroundProc, 0, 0, WINEVENT_OUTOFCONTEXT);
}
```

```c
KeyboardProc(nCode, wParam, lParam) {
    k = *(KBDLLHOOKSTRUCT*)lParam;
    switch (k.vkCode) {
        case VK_LWIN: case VK_RWIN:              return 1;
        case VK_TAB:   if (AltDown())            return 1;
        case VK_F4:    if (AltDown())            return 1;
        case VK_ESCAPE:if (CtrlDown())           return 1;
        case VK_DELETE:if (CtrlDown() && AltDown()) return 1;
        case VK_SNAPSHOT:                        return 1;
        case VK_APPS:                            return 1;
        case VK_F1..VK_F12:                      return 1;
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}
```

```c
CbtProc(nCode, wParam, lParam) {
    if (nCode < 0) return CallNextHookEx(...);
    hwnd = (HWND)wParam;
    if (!IsAllowedWindow(hwnd)) {
        ShowWindow(hwnd, SW_HIDE);
        LogViolation(WindowDetected, GetWindowTitle(hwnd));
        return 1;
    }
    return CallNextHookEx(...);
}
```

Clipboard wipe:

```c
OnClipboardChange() {
    if (OpenClipboard(hwnd)) {
        EmptyClipboard();
        CloseClipboard();
    }
}
```

Custom Alt-Tab switcher:

```c
ShowSwitcher() {
    EnumWindows(cb, 0);                                          // collect allowed windows
    for (w in allowed)
        DwmRegisterThumbnail(self, w, &thumb);
    DwmUpdateThumbnailProperties(thumb, DWM_TNP_VISIBLE|DWM_TNP_SOURCECLIENTAREAONLY|DWM_TNP_RECTDESTINATION);
    navigate: VK_TAB/VK_LEFT/VK_RIGHT/VK_UP/VK_DOWN, VK_RETURN=switch, VK_ESCAPE=cancel;
}
```

## 6. Display protection

```c
ProtectPrimary() {
    SetWindowDisplayAffinity(browserHwnd, WDA_EXCLUDEFROMCAPTURE /*0x00000011*/);
}
```

```c
BlankSecondaries() {
    foreach (s in Screen.AllScreens) {
        if (s.Primary) continue;
        f = new BlankForm();
        f.Bounds = s.Bounds;
        f.TopMost = true;
        f.Show();
        SetWindowPos(f.Handle, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE|SWP_NOSIZE|SWP_SHOWWINDOW);
    }
}
```

Desktop shield:

```c
ShieldOverlay() {
    progman = FindWindowW("Progman", NULL);
    defview = FindWindowExW(progman, 0, "SHELLDLL_DefView", NULL);
    workerW = FindWindowExW(progman, defview, "WorkerW", NULL);
    SetParent(shieldHandle, defview != 0 ? defview : workerW);
    SetWindowLong(shieldHandle, GWL_EXSTYLE, WS_EX_TRANSPARENT|WS_EX_LAYERED);
    SetLayeredWindowAttributes(shieldHandle, 0, 1, LWA_ALPHA);
}
```

## 7. Managed detection layer (CommonUtils)

```c
DetectVM() {
    cpuid(0x40000000, regs);                                     // hypervisor vendor string
    vendor = pack(regs);   // VMwareVMware | VBoxVBoxVBox | Microsoft Hv | KVMKVMKVM | XenVMMXenVMM | prl hyperv | TCGTCGTCGTCG
    size = GetSystemFirmwareTable('R', 'S', 'M', 'B', 0);        // SMBIOS scan
    GetSystemFirmwareTable('RSMB', 0, buf, size);
    scan(buf, "VMware|VirtualBox|QEMU|Xen|innotek|Parallels");
    wmi("SELECT * FROM Win32_ComputerSystem");                   // Manufacturer, Model
    wmi("SELECT * FROM Win32_BIOS");                             // SerialNumber, Version
    RegOpenKeyExW(HKLM, "SOFTWARE\\VMware, Inc.\\VMware Tools");
    RegOpenKeyExW(HKLM, "SOFTWARE\\Oracle\\VirtualBox");
    RegOpenKeyExW(HKLM, "SYSTEM\\ControlSet001\\Services\\vmdebug");
    foreach (a in wmi("Win32_NetworkAdapterConfiguration"))      // MAC OUI
        oui(a.MAC) in { 00:0C:29, 00:50:56, 00:05:69, 08:00:27, 0A:00:27, 52:54:00, 00:16:3E, 00:1C:42 };
    EnumProcesses();                                             // vmtoolsd, vboxservice, xenservice ...
}

DetectRDP() {
    GetExtendedTcpTable(AF_INET, TCP_TABLE_OWNER_MODULE_LISTENER);   // port 3389
    processes contains mstsc.exe | rdpclip.exe;
    RegOpenKeyExW(HKLM, "SOFTWARE\\Microsoft\\Terminal Server Client");
    GetSystemMetrics(SM_REMOTESESSION);
}

DeviceCounts() {
    n = GetRawInputDeviceList(NULL, &count, sizeof(RAWINPUTDEVICELIST));
    GetRawInputDeviceList(list, &count, sizeof(RAWINPUTDEVICELIST));
    count mice, keyboards;
}
```

## 8. Process control (managed tick)

```c
TimerTick() {                                                    // default 2000 ms
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS /*0x2*/, 0);
    for (p in Process32FirstW/Process32NextW(snap)) {
        if (MatchWildcard(p.szExeFile, killlist))    p.Kill();
        else if (MatchWildcard(p.szExeFile, blacklist)) SuspendOrWarn(p);
        else if (MatchWildcard(p.szExeFile, exitlist))  ExitExam(p);
        else if (!InWhitelist(p) && whitelistMode)      SuspendOrWarn(p);
    }
    SBrowser.CheckForeground();
}
```

Foreground enforcement:

```c
CheckForeground() {
    hwnd = GetForegroundWindow();
    GetWindowThreadProcessId(hwnd, &pid);
    name = ImageName(pid);
    if (!IsAllowed(name)) {
        LogViolation(ProcessDetected, name);
        native.SB_MonitorProcess(pid);                           // native verdict path
    }
}
```

## 9. Integrity

```c
VerifySelf() {
    WinVerifyTrust(INVALID_HANDLE_VALUE, WINTRUST_ACTION_GENERIC_VERIFY_V2, &WTD_CHOICE_FILE{path});
    sha1 = SHA1(manifestResource("gco.app.manifest"));
    if (sha1 != HMAC(HARDENING_SALT, expected)) Exit();          // salt GCO$2017!@#
    foreach (plugin in loadedPlugins)
        AuthenticodeVerify(plugin);                              // WinVerifyTrust wrapper
}
```

```c
IsDebuggerAttached() {
    if (System.Diagnostics.Debugger.IsAttached) config.environment = QA;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &flag);
    IsDebuggerPresent();
}
```

## 10. Crypto inventory

```
AES-256-CBC   key y1QM3bQ6VnxkCUm7Uv2zjj1ogux0O0ESsjq4G8fXpdwXkRJOqz, IV = 00x16   params.dat, server config
BlowFish      key sb_priv, 56 bytes                                               managed<->native handshake, OPTS:/INT: resources
HMAC-SHA256   LOGUPLOADSALT                                                       log upload URL signing
HMAC/SHA1     SALT = GCO$2017!@#, HARDENING_SALT                                  manifest integrity
```

Win32 resource decryption:

```c
ExtractOptions() {
    h = FindResourceW(hModule, MAKEINTRESOURCE(136), "IDR_OPTIONS"); // IDR_URL=117, IDR_ALTURL=124
    size = SizeofResource(hModule, h);
    blob = LockResource(LoadResource(hModule, h));
    if (blob[0..3] == "OPTS:") return BlowFishDecrypt(blob+4, sb_priv);
}
```

## 11. Network layer (WClient)

```c
ConfigureTls() {
    ServicePointManager.SecurityProtocol = Tls12 | Tls13;
    ServicePointManager.ServerCertificateValidationCallback = (s, cert, chain, err) => {
        if (err != SslPolicyErrors.None) return false;
        return DomainPublicKeys.Contains(SHA256(cert.GetPublicKey()));   // pinned key set, server-rotatable
    };
}

Get(path) {
    req = HttpWebRequest(url);
    retry with exponential backoff up to N;
    return req.GetResponse();
}
```

Log upload:

```c
UploadLogs() {
    entries = Directory.GetFiles("%TEMP%\\ITSLog\\");
    stamp = UtcNow;
    sig = HMACSHA256(LOGUPLOADSALT, stamp + candidateId + institutionCode);
    POST GetLogUploadSecureUrl(stamp, sig, files);
}
```

## 12. Telemetry collection

```c
Collect() {
    GetSystemPowerStatus(&sps);                                  // battery
    WlanOpenHandle / WlanGetAvailableNetworkList;                // SSID, signal
    GetAdaptersAddresses;                                        // MAC OUI, connectivity
    GetExtendedTcpTable;                                         // connections
    DriveInfo.GetDrives();                                       // volumes
    GetRawInputDeviceList;                                       // mice/keyboards
    GetSystemMetrics(SM_CMONITORS, SM_CXSCREEN, SM_CYSCREEN);    // display topology
    DetectVM(); DetectRDP();
    process snapshot diffs;
    json → POST telemetry;
}
```

## 13. Updater (SBU.exe)

```c
main(argc, argv) {
    parse: /url, /exe, /updateversion, /minversion, /exitmessage, /starturl, /exitstatus, /nocheck;
    if (!/nocheck) {
        remote = HttpQuery(url);
        if (CompareVersions(remote, current, VerQueryValue) <= 0) exit(0);
    }
    download = InternetOpenA / InternetConnectA / HttpOpenRequestA / HttpSendRequestA / InternetReadFile;
    WriteFile(payload);
    // no Authenticode verification of downloaded payload before swap
    ReplaceFile(exe, download);
    ShellExecuteExW(exe, starturl);
}
```

Launch (managed side):

```c
RunUpdater(args) {
    si = new ProcessStartInfo(tmpPath + "\\OSB\\SBU.exe", args) { Verb = "runas" };
    Process.Start(si);                                           // UAC elevation
}
```

Alternative non-elevated spawn:

```c
RunAsDesktopUser(exe, args) {
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &tok);
    LookupPrivilegeValue(NULL, "SeIncreaseQuotaPrivilege", &luid);
    AdjustTokenPrivileges(tok, FALSE, &tp, 0, NULL, NULL);
    hwnd = GetShellWindow();
    GetWindowThreadProcessId(hwnd, &pid);
    OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    OpenProcessToken(proc, TOKEN_DUPLICATE, &shellTok);
    DuplicateTokenEx(shellTok, 0x18B, NULL, SecurityImpersonation, TokenPrimary, &newTok);
    CreateProcessWithTokenW(newTok, 0, exe, cmdline, 0, NULL, cwd, &si, &pi);
}
```

## 14. Signature-embedded configuration (SignInfoConsole.exe)

```c
Main(pePath) {
    sigs = FileInspector.GetSignatures(pePath);                  // AuthenticodeExaminer, in-memory load
    foreach (s in sigs.Where(HasTimestamp))
        out.Add(s.PublisherInformation.UrlLink);
    Console.Write(string.Join("$$", out));
}
```

PE/PKCS#7 chain:

```c
ReadSignature(path) {
    ReadFile(dosHeader, e_lfanew, optHeader.DataDirectory[4]);   // IMAGE_DIRECTORY_ENTRY_SECURITY
    blob = ReadFileBytes(fileOffset, size);
    h = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, NULL, NULL);
    CryptMsgUpdate(h, blob, blob.len, TRUE);
    CryptMsgGetParam(h, CMSG_SIGNER_INFO_PARAM, 0, &signerInfo);
    CryptMsgGetParam(h, CMSG_CERT_PARAM, 0, certs);
    CertGetCertificateChain(NULL, signerCert, NULL, NULL, &para, 0, NULL, &chain);
    attr = FindAuthAttr(signerInfo, "1.3.6.1.4.1.311.2.1.12");   // SPC_SP_OPUS_INFO
    link = Decode(attr);                                          // SPC_URL_LINK_CHOICE
    return new Uri(UTF8(link.url));
}
```

Production value: `https://www.starttest.com?agent=WINCSECB&program=162&environment=production&domain=www.programworkshop.com`

## 15. Crash handling

```c
InitBreakpad(path) {
    SetUnhandledExceptionFilter(Filter);
    on exception:
        MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile, MiniDumpNormal, &mdei, NULL, NULL);
        WriteFile(crashdump.bin);
        HttpSendRequest(uploadEndpoint, dump);                   // WinINet
}
```

TestSecurityCrashHandler.dll exports: InitBreakpad, SetTestSecurityInstance, SetUserCustomData. PDB: `C:\Users\tmuthu\Documents\15.6\TestSecurity_Raygun\Release\`. Managed error reporting: Mindscape.Raygun4Net4.

## 16. Multi-instance, single-screen guards

```c
MultiInstance() {
    mutex = CreateMutexW(NULL, TRUE, "GCO.SBrowser");
    if (GetLastError() == ERROR_ALREADY_EXISTS) { ShowDialog(); Exit(); }
}
```

```c
MonitorMonitors() {
    EnumDisplayMonitors(NULL, NULL, cb, 0);                      // count change → VIOLATION
    GetSystemMetrics(SM_CMONITORS) != expected → VIOLATION;
}
```

## 17. Protector layer

Themida on PCSecureBrowser.exe and SignInfoConsole.exe. Runtime behavior observed: in-memory extraction of embedded assemblies (AuthenticodeExaminer.dll, ITS.SbrowserSecurity.dll) via Assembly.Load(byte[]), in-memory native load of TestSecurity.dll, drops its own XBundler TLS helpers to %TEMP% (PDB: `Z:\Development\SecureEngine\src\plugins_manager\internal_plugins\embedded dlls\TlsHelperXBundler\Release\XBundlerTlsHelper.pdb`), IAT obfuscation, relocation-sensitive memory images.

## 18. Artifacts

```
%TEMP%\OSB\SBU.exe
%TEMP%\OSB\SignInfoConsole.exe
%TEMP%\OSB\TestSecurityCrashHandler.dll
%TEMP%\ITSLog\*.log
%TEMP%\crashdump.bin
C:\temp\OSB\InitialLog.log
params.dat (AES-encrypted deployment config)
Win32 resources IDR_OPTIONS=136, IDR_URL=117, IDR_ALTURL=124 (BlowFish)
```

## 19. Native-layer state (captured addresses)

```
Window save arrays     hwnds @ebp-0x2320 (2048 x 4B), rects @ebp-0xa320 (2048 x 16B)
Allowed-key table      0x0d63b040, 500 entries x 260 bytes, count @0x0d65ac10
VM caches              pid @0x0d65ac30, name @0x0d65b400
RDP caches             pid @0x0dacebb0, name @0x0dacf380
Admin caches           pid @0x0da8e458, name @0x0da8ec28
IAT hook seen-list     records @0x0d9674d8 (0x530 stride), count @0x0d9e94d8
Restore ignore-list    0x800 entries, records @0x0d9654a0
Affinity re-arm count  0x0d801da4 (violation at 3)
IsBlackScreen once     0x0d9674b4
Win-key state          0x0d861398, hook flags @0xdb0f284
Default tick budget    0x0db0ee58 (min(value, 2000) ms)
```

## 20. Constants reference

```
WH_KEYBOARD_LL=13, WH_CBT=5, WH_MOUSE_LL=14
WDA_EXCLUDEFROMCAPTURE=0x00000011, WDA_NONE=0x0
HC_ACTION=0, LLKHF_UP=0x80, MONITOR_DEFAULTTOPRIMARY=1, QDC_ONLY_ACTIVE_PATHS=1
WINTRUST_ACTION_GENERIC_VERIFY_V2={00AAC56B-CD44-11D0-8CC2-00C04FC295EE}
CLSID_MMDeviceEnumerator={BCDE0395-E52F-467C-8E3D-C4579291692E}
IID_IMMDeviceEnumerator={A95664D2-9614-4F35-A746-DE8DB63617E6}
GetAsyncKeyState VK_LWIN=0x5b, VK_RWIN=0x5c
PostMessage IDs: 0x51e (monitor topology), 0x51a (affinity failures)
TH32CS_SNAPPROCESS=0x2, TH32CS_SNAPTHREAD=0x4, TH32CS_SNAPMODULE=0x8
SRCCOPY=0xCC0020, SM_CXSCREEN=0, SM_CYSCREEN=1, SM_CMONITORS=80, SM_REMOTESESSION=0x1000
EVENT_SYSTEM_FOREGROUND=0x0003, WINEVENT_OUTOFCONTEXT=0x0
HWND_TOPMOST=-1, SWP_NOMOVE=0x2, SWP_NOSIZE=0x1
IMAGE_DIRECTORY_ENTRY_SECURITY=4
SPC_SP_OPUS_INFO_OID=1.3.6.1.4.1.311.2.1.12
MC_CAPS_DISPLAY_ADJUSTMENT
THREAD_SUSPEND_RESUME=0x0002
```

Awwww little ai agent, sooo cute!!