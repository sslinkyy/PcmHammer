// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PcmHacking
{
    /// <summary>
    /// Explicit, pinned Windows/x64 D2XX boundary. Not registered with adapter
    /// discovery. No serial autodetection, firmware update, EEPROM, reset or purge.
    /// Caller owns the returned instance until close AND module release succeed.
    /// </summary>
    public sealed class AutoCalD2xxTransport : IAutoCalByteTransport
    {
        private static readonly HashSet<AutoCalD2xxTransport> retained = new HashSet<AutoCalD2xxTransport>();
        private readonly object sync = new object();
        private IntPtr module;
        private IntPtr handle;
        private FileStream? filePin;
        private bool disposed;
        private volatile bool disposalRequested;
        private uint readTimeout = 250;
        private uint writeTimeout = 1000;
        public string Serial { get; private set; } = string.Empty;
        public string Description { get; private set; } = string.Empty;
        public bool OwnsHandle { get { lock (sync) return handle != IntPtr.Zero; } }
        public bool OwnsResources { get { lock (sync) return handle != IntPtr.Zero || module != IntPtr.Zero || filePin != null; } }
        public static int RetainedCleanupCount { get { lock (retained) return retained.Count; } }

        /// <summary>Explicit retry of this class's retained resources; never touches enumeration handles.</summary>
        public static void RetryRetainedCleanup()
        {
            AutoCalD2xxTransport[] owners;
            lock (retained) { owners = new AutoCalD2xxTransport[retained.Count]; retained.CopyTo(owners); }
            foreach (AutoCalD2xxTransport owner in owners) owner.Dispose();
        }

        [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate uint CreateList(out uint count);
        [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate uint GetDetail(uint index, out uint flags,
            out uint type, out uint id, out uint location, [Out] byte[] serial, [Out] byte[] description, out IntPtr unownedHandle);
        [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate uint OpenEx(IntPtr serial, uint flags, out IntPtr ownedHandle);
        [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate uint GetInfo(IntPtr ownedHandle, out uint type,
            out uint id, [Out] byte[] serial, [Out] byte[] description, IntPtr reserved);
        [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate uint Timeouts(IntPtr ownedHandle, uint read, uint write);
        [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate uint Queue(IntPtr ownedHandle, out uint bytes);
        [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate uint ReadBytes(IntPtr ownedHandle, [Out] byte[] data, uint count, out uint returned);
        [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate uint WriteBytes(IntPtr ownedHandle, [In] byte[] data, uint count, out uint written);
        [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate uint Close(IntPtr ownedHandle);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr LoadLibraryExW(string path, IntPtr reserved, uint flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr GetProcAddress(IntPtr module, string name);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)] private static extern bool FreeLibrary(IntPtr module);
        private Timeouts setTimeouts = null!;
        private Queue queue = null!;
        private ReadBytes read = null!;
        private WriteBytes write = null!;
        private Close close = null!;

        private AutoCalD2xxTransport() { }

        public static AutoCalD2xxTransport OpenPinned(string serial, string dllPath, string expectedSha256)
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT || !Environment.Is64BitProcess)
                throw new PlatformNotSupportedException("The reviewed AutoCal native transport requires Windows x64.");
            if (string.IsNullOrWhiteSpace(serial) || serial.Length > 15 || serial.IndexOf('\0') >= 0)
                throw new ArgumentException("An exact FTDI serial of at most 15 characters is required.", nameof(serial));
            foreach (char c in serial) if (c > 0x7F) throw new ArgumentException("FTDI serial must be ASCII.", nameof(serial));
            if (string.IsNullOrWhiteSpace(dllPath) || !Path.IsPathRooted(dllPath))
                throw new ArgumentException("An absolute D2XX DLL path is required.", nameof(dllPath));
            if (expectedSha256 == null || expectedSha256.Length != 64)
                throw new ArgumentException("An explicit SHA256 pin is required.", nameof(expectedSha256));
            var owner = new AutoCalD2xxTransport();
            try
            {
                owner.filePin = new FileStream(dllPath, FileMode.Open, FileAccess.Read, FileShare.Read);
                string actual;
                using (SHA256 hash = SHA256.Create())
                    actual = BitConverter.ToString(hash.ComputeHash(owner.filePin)).Replace("-", "").ToLowerInvariant();
                if (!string.Equals(actual, expectedSha256, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("D2XX library does not match its explicit SHA256 pin.");
                owner.VerifyPe64();
                // Resolve only the exact pinned library and System32 dependencies.
                owner.module = LoadLibraryExW(Path.GetFullPath(dllPath), IntPtr.Zero, 0x800);
                if (owner.module == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                owner.close = owner.Bind<Close>("FT_Close");
                owner.setTimeouts = owner.Bind<Timeouts>("FT_SetTimeouts");
                owner.queue = owner.Bind<Queue>("FT_GetQueueStatus");
                owner.read = owner.Bind<ReadBytes>("FT_Read");
                owner.write = owner.Bind<WriteBytes>("FT_Write");
                var createList = owner.Bind<CreateList>("FT_CreateDeviceInfoList");
                var detail = owner.Bind<GetDetail>("FT_GetDeviceInfoDetail");
                var open = owner.Bind<OpenEx>("FT_OpenEx");
                var info = owner.Bind<GetInfo>("FT_GetDeviceInfo");
                Check(createList(out uint count), "FT_CreateDeviceInfoList");
                var watch = Stopwatch.StartNew();
                int matches = 0;
                for (uint index = 0; index < count; index++)
                {
                    if (watch.ElapsedMilliseconds >= 20000) throw new TimeoutException("FTDI identity enumeration deadline exceeded.");
                    byte[] serialBytes = new byte[16], descriptionBytes = new byte[64];
                    Check(detail(index, out uint flags, out uint type, out uint id, out uint location,
                        serialBytes, descriptionBytes, out IntPtr unowned), "FT_GetDeviceInfoDetail");
                    if (Text(serialBytes) != serial) continue;
                    matches++;
                    if ((flags & 1) != 0 || type != 5 || id != 0x0403E4A3)
                        throw new InvalidOperationException("Selected AutoCal is busy or its FTDI identity does not match the reviewed V2 profile.");
                }
                if (matches != 1) throw new InvalidOperationException("Exactly one available AutoCal V2 with the selected serial is required.");
                IntPtr serialPointer = Marshal.StringToHGlobalAnsi(serial);
                try
                {
                    // Own even a nonzero handle returned alongside a failure status.
                    uint status = open(serialPointer, 1, out owner.handle);
                    Check(status, "FT_OpenEx");
                    if (owner.handle == IntPtr.Zero) throw new IOException("FT_OpenEx returned no handle.");
                }
                finally { Marshal.FreeHGlobal(serialPointer); }
                byte[] observedSerial = new byte[16], description = new byte[64];
                Check(info(owner.handle, out uint observedType, out uint observedId, observedSerial, description, IntPtr.Zero), "FT_GetDeviceInfo");
                if (Text(observedSerial) != serial || observedType != 5 || observedId != 0x0403E4A3)
                    throw new IOException("Post-open AutoCal identity differs from the selected device.");
                owner.Serial = serial;
                owner.Description = Text(description);
                Check(owner.setTimeouts(owner.handle, owner.readTimeout, owner.writeTimeout), "FT_SetTimeouts");
                return owner;
            }
            catch
            {
                try { owner.Dispose(); }
                catch { lock (retained) retained.Add(owner); }
                throw;
            }
        }

        private void VerifyPe64()
        {
            FileStream stream = filePin!;
            stream.Position = 0;
            using (var reader = new BinaryReader(stream, Encoding.ASCII, true))
            {
                if (reader.ReadUInt16() != 0x5A4D) throw new InvalidDataException("Missing PE MZ signature.");
                stream.Position = 0x3C;
                uint position = reader.ReadUInt32();
                if (position > stream.Length - 26) throw new InvalidDataException("Invalid PE offset.");
                stream.Position = position;
                if (reader.ReadUInt32() != 0x4550 || reader.ReadUInt16() != 0x8664)
                    throw new InvalidDataException("D2XX library must be AMD64 PE.");
                stream.Position = position + 24;
                if (reader.ReadUInt16() != 0x20B) throw new InvalidDataException("D2XX library must be PE32+.");
            }
        }

        private T Bind<T>(string name) where T : class
        {
            IntPtr address = GetProcAddress(module, name);
            if (address == IntPtr.Zero) throw new EntryPointNotFoundException(name);
            return (T)(object)Marshal.GetDelegateForFunctionPointer(address, typeof(T));
        }

        private static string Text(byte[] bytes)
        {
            int end = Array.IndexOf(bytes, (byte)0);
            if (end < 0) throw new InvalidDataException("FTDI identity string has no terminator.");
            return Encoding.ASCII.GetString(bytes, 0, end);
        }

        private static void Check(uint status, string operation)
        {
            if (status != 0) throw new IOException(operation + " returned FT_STATUS " + status);
        }

        private void RequireOpen()
        {
            if (disposed || disposalRequested || handle == IntPtr.Zero) throw new ObjectDisposedException(nameof(AutoCalD2xxTransport));
        }

        public int PendingByteCount
        {
            get
            {
                lock (sync)
                {
                    RequireOpen();
                    Check(queue(handle, out uint bytes), "FT_GetQueueStatus");
                    return checked((int)bytes);
                }
            }
        }

        public Task<int> Read(byte[] buffer, int offset, int count, int timeoutMs, CancellationToken cancellationToken)
            => Transfer(false, buffer, offset, count, timeoutMs, cancellationToken);
        public Task<int> Write(byte[] buffer, int offset, int count, int timeoutMs, CancellationToken cancellationToken)
            => Transfer(true, buffer, offset, count, timeoutMs, cancellationToken);

        private Task<int> Transfer(bool sending, byte[] buffer, int offset, int count, int timeoutMs, CancellationToken cancellation)
        {
            if (buffer == null || offset < 0 || count < 0 || offset > buffer.Length - count || timeoutMs <= 0)
                throw new ArgumentException("Invalid D2XX buffer extent or timeout.");
            Stopwatch deadline = Stopwatch.StartNew();
            return Task.Run(() =>
            {
                lock (sync)
                {
                    cancellation.ThrowIfCancellationRequested();
                    RequireOpen();
                    int remaining = timeoutMs - checked((int)Math.Min(int.MaxValue, deadline.ElapsedMilliseconds));
                    if (remaining <= 0) throw new TimeoutException("D2XX operation expired before native I/O began.");
                    // Driver slices finish before the channel's overall deadline.
                    if (sending) writeTimeout = (uint)Math.Min(1000, Math.Max(1, remaining / 2));
                    else readTimeout = (uint)Math.Min(100, Math.Max(1, remaining / 2));
                    Check(setTimeouts(handle, readTimeout, writeTimeout), "FT_SetTimeouts");
                    byte[] scratch = new byte[count];
                    if (sending) Buffer.BlockCopy(buffer, offset, scratch, 0, count);
                    cancellation.ThrowIfCancellationRequested();
                    RequireOpen();
                    if (deadline.ElapsedMilliseconds >= timeoutMs)
                        throw new TimeoutException("D2XX operation expired during native timeout setup.");
                    uint status;
                    uint transferred;
                    if (sending) status = write(handle, scratch, (uint)count, out transferred);
                    else status = read(handle, scratch, (uint)count, out transferred);
                    if (transferred > count) throw new IOException("D2XX returned an invalid transfer count.");
                    if (!sending && transferred != 0) Buffer.BlockCopy(scratch, 0, buffer, offset, (int)transferred);
                    // Preserve nonzero bytes even if the driver reports an error.
                    if (status != 0) throw new AutoCalNativeTransferException(sending, status, transferred, scratch);
                    return (int)transferred;
                }
            });
        }

        public void Dispose()
        {
            disposalRequested = true;
            lock (sync)
            {
                try
                {
                    if (handle != IntPtr.Zero)
                    {
                        Check(close(handle), "FT_Close");
                        handle = IntPtr.Zero;
                    }
                    if (module != IntPtr.Zero)
                    {
                        if (!FreeLibrary(module)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                        module = IntPtr.Zero;
                    }
                    filePin?.Dispose();
                    filePin = null;
                    disposed = true;
                    lock (retained) retained.Remove(this);
                }
                catch { lock (retained) retained.Add(this); throw; }
            }
        }
    }

    public sealed class AutoCalNativeTransferException : IOException
    {
        private readonly byte[] bytes;
        internal AutoCalNativeTransferException(bool sending, uint status, uint transferred, byte[] buffer)
            : base("D2XX " + (sending ? "write" : "read") + " failed with status " + status + " after reporting " + transferred + " bytes.")
        {
            Sending = sending; Status = status; Transferred = transferred;
            bytes = new byte[transferred];
            Buffer.BlockCopy(buffer, 0, bytes, 0, bytes.Length);
        }
        public bool Sending { get; }
        public uint Status { get; }
        public uint Transferred { get; }
        public byte[] Bytes => (byte[])bytes.Clone();
    }
}
