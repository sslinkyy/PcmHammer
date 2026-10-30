// SPDX-License-Identifier: GPL-3.0-only
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace AutoCalModelProbe;

internal interface IRetainedResources
{
    bool OwnsHandle { get; }
    bool OwnsLibraryOrPin { get; }
    int CloseAttempts { get; }
    uint CloseOwnedHandle();
    bool TryReleaseLibrary(out string? error);
}

internal sealed class D2xxNative : IModelDevice, IRetainedResources
{
    internal const string DllPath = @"C:\Program Files (x86)\EFILive\Drivers\EFILive\Win-7-8-10\amd64\ftd2xx64.dll";
    internal const string DllSha256 = "91185415e0a1cd8ad09a5b644130554867ee4c4975c7aa71ee6da15d2645d9a2";
    internal const string HeaderPath = @"C:\Program Files (x86)\EFILive\Drivers\EFILive\Win-7-8-10\ftd2xx.h";
    internal const string HeaderSha256 = "cf2ad290c68137373b26629bf9feed6f4847f4e9e5cde4b980a212cebeb4ff6a";
    private readonly ProbeBudget budget;
    private FileStream? pin;
    private IntPtr module;
    private IntPtr ownedHandle;
    public bool OwnsHandle => ownedHandle != IntPtr.Zero;
    public bool OwnsLibraryOrPin => module != IntPtr.Zero || pin != null;
    public int CloseAttempts { get; private set; }

    // Prototypes verified against the hash-pinned installed ftd2xx.h:
    // WINAPI; FT_STATUS/ULONG/DWORD = uint32; FT_HANDLE/PVOID = pointer-width.
    // Lines 339-372, 460-471, 1309-1330; flags at 114, buffer sizes at 1292-1300.
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate uint CreateList(out uint count);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate uint GetDetail(uint index,
        out uint flags, out uint type, out uint id, out uint location,
        [Out] byte[] serial, [Out] byte[] description, out IntPtr unusedHandle);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate uint OpenEx(IntPtr serial, uint flags, out IntPtr handle);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate uint SetTimeouts(IntPtr handle, uint readMs, uint writeMs);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate uint QueueStatus(IntPtr handle, out uint count);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate uint Write(IntPtr handle, [In] byte[] data, uint count, out uint written);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate uint ReadBytes(IntPtr handle, [Out] byte[] data, uint count, out uint returned);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate uint Close(IntPtr handle);
    private CreateList createList = null!;
    private GetDetail getDetail = null!;
    private OpenEx openEx = null!;
    private SetTimeouts setTimeouts = null!;
    private QueueStatus queueStatus = null!;
    private Write write = null!;
    private ReadBytes read = null!;
    private Close close = null!;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr LoadLibraryExW(string fileName, IntPtr reserved, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr GetProcAddress(IntPtr module, string name);
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool FreeLibrary(IntPtr module);

    internal D2xxNative(ProbeBudget budget) { this.budget = budget; }

    internal static string HashFile(string path)
    {
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    // File-only verification: safe for --plan and tests; no native library load.
    internal static object VerifyFiles()
    {
        string dllHash = HashFile(DllPath);
        string headerHash = HashFile(HeaderPath);
        if (dllHash != DllSha256 || headerHash != HeaderSha256)
            throw new InvalidDataException("D2XX DLL or primary ABI header changed; review required.");
        using FileStream stream = new(DllPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        VerifyAmd64(stream);
        return new { DllPath, DllSha256, HeaderPath, HeaderSha256, Architecture = "AMD64 PE32+", Exports = FixedModel.ExportNames };
    }

    private static void VerifyAmd64(FileStream stream)
    {
        using BinaryReader reader = new(stream, Encoding.ASCII, leaveOpen: true);
        stream.Position = 0;
        if (reader.ReadUInt16() != 0x5A4D) throw new InvalidDataException("Missing MZ header.");
        stream.Position = 0x3C;
        uint pe = reader.ReadUInt32();
        if (pe > stream.Length - 26) throw new InvalidDataException("Invalid PE offset.");
        stream.Position = pe;
        if (reader.ReadUInt32() != 0x4550 || reader.ReadUInt16() != 0x8664)
            throw new InvalidDataException("An AMD64 PE library is required.");
        stream.Position = pe + 24;
        if (reader.ReadUInt16() != 0x20B) throw new InvalidDataException("PE32+ is required.");
    }

    internal void LoadVerified()
    {
        if (!OperatingSystem.IsWindows() || !Environment.Is64BitProcess)
            throw new PlatformNotSupportedException("Live model query requires a 64-bit Windows process.");
        if (pin != null || module != IntPtr.Zero) throw new InvalidOperationException("This boundary cannot be reopened.");
        budget.Check();
        // No write/delete sharing: source bytes remain pinned through close/unload.
        pin = new FileStream(DllPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (Convert.ToHexString(SHA256.HashData(pin)).ToLowerInvariant() != DllSha256
            || HashFile(HeaderPath) != HeaderSha256)
            throw new InvalidDataException("Pinned DLL or primary header hash mismatch.");
        VerifyAmd64(pin);
        budget.Check();
        // Exact absolute DLL; only System32 is searched for dependencies.
        module = LoadLibraryExW(DllPath, IntPtr.Zero, 0x800);
        if (module == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        createList = Bind<CreateList>("FT_CreateDeviceInfoList");
        getDetail = Bind<GetDetail>("FT_GetDeviceInfoDetail");
        openEx = Bind<OpenEx>("FT_OpenEx");
        setTimeouts = Bind<SetTimeouts>("FT_SetTimeouts");
        queueStatus = Bind<QueueStatus>("FT_GetQueueStatus");
        write = Bind<Write>("FT_Write");
        read = Bind<ReadBytes>("FT_Read");
        close = Bind<Close>("FT_Close");
    }

    private T Bind<T>(string name) where T : Delegate
    {
        if (!FixedModel.ExportNames.Contains(name)) throw new InvalidOperationException("Export is outside the fixed model allowlist.");
        IntPtr pointer = GetProcAddress(module, name);
        if (pointer == IntPtr.Zero) throw new EntryPointNotFoundException(name);
        return Marshal.GetDelegateForFunctionPointer<T>(pointer);
    }

    public Enumeration Enumerate()
    {
        budget.Check();
        uint status = createList(out uint count);
        List<Identity> entries = [];
        if (status != 0 || count > 64) return new Enumeration(status, count, entries);
        for (uint i = 0; i < count; i++)
        {
            budget.Check();
            byte[] serial = new byte[16], description = new byte[64];
            status = getDetail(i, out uint flags, out uint type, out uint id, out uint location,
                serial, description, out IntPtr preexisting);
            int zero = Array.IndexOf(serial, (byte)0);
            entries.Add(new Identity(i, status, flags, type, id, location,
                Convert.ToHexString(serial.AsSpan(0, zero < 0 ? serial.Length : zero)),
                Convert.ToHexString(serial), zero >= 0, Convert.ToHexString(description), preexisting != IntPtr.Zero));
            // API-returned preexisting handle is observed only; never used/closed.
            if (status != 0) break;
        }
        return new Enumeration(status, count, entries);
    }

    public OpenResult OpenExactSerial()
    {
        if (OwnsHandle) throw new InvalidOperationException("Handle already owned.");
        budget.Check();
        IntPtr serial = Marshal.StringToHGlobalAnsi(FixedModel.Serial);
        try
        {
            uint status = openEx(serial, 1, out IntPtr handle);
            if (status == 0 && handle != IntPtr.Zero) ownedHandle = handle;
            return new OpenResult(status, handle != IntPtr.Zero);
        }
        finally { Marshal.FreeHGlobal(serial); }
    }

    private IntPtr ReadyHandle()
    {
        budget.Check();
        if (!OwnsHandle) throw new InvalidOperationException("No owned device handle.");
        return ownedHandle;
    }
    public uint SetFixedTimeouts() => setTimeouts(ReadyHandle(), FixedModel.ReadTimeoutMs, FixedModel.WriteTimeoutMs);
    public CountResult GetQueueStatus()
    {
        uint status = queueStatus(ReadyHandle(), out uint count);
        return new CountResult(status, count);
    }
    public CountResult WriteFixedModelQuery()
    {
        byte[] query = FixedModel.Query();
        uint status = write(ReadyHandle(), query, 14, out uint count);
        return new CountResult(status, count);
    }
    public ReadResult Read(int count)
    {
        if (count < 1 || count > FixedModel.ReplyBytes) throw new ArgumentOutOfRangeException(nameof(count));
        byte[] data = new byte[count];
        uint status = read(ReadyHandle(), data, (uint)count, out uint returned);
        // Preserve reported count separately; never copy beyond the allocated buffer.
        return new ReadResult(status, returned, data.AsSpan(0, (int)Math.Min((uint)count, returned)).ToArray());
    }
    public uint CloseOwnedHandle()
    {
        if (!OwnsHandle) throw new InvalidOperationException("No owned handle to close.");
        CloseAttempts++;
        uint status = close(ownedHandle); // Cleanup remains allowed after deadline/cancellation.
        if (status == 0) ownedHandle = IntPtr.Zero;
        return status;
    }

    public bool TryReleaseLibrary(out string? error)
    {
        error = null;
        if (OwnsHandle) { error = "Owned device handle remains; DLL and file pin retained."; return false; }
        if (module != IntPtr.Zero)
        {
            if (!FreeLibrary(module)) { error = $"FreeLibrary failed: {Marshal.GetLastWin32Error()}"; return false; }
            module = IntPtr.Zero;
        }
        try { pin?.Dispose(); pin = null; }
        catch (Exception failure) { error = failure.ToString(); return false; }
        return true;
    }
}
