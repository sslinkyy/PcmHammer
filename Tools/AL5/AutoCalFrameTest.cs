// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.IO;
using System.Text.Json;
using PcmHacking;

internal static class AutoCalFrameTest
{
    private static int assertions;

    public static int Main(string[] args)
    {
        string corpusPath = args.Length == 0
            ? Path.Combine(AppContext.BaseDirectory, "Fixtures", "autocal_htx_envelope_cases.json")
            : args.Length == 1 ? args[0] : throw new ArgumentException("Expected zero arguments or one corpus path.");
        using var corpus = JsonDocument.Parse(File.ReadAllText(corpusPath));
        Require(corpus.RootElement.GetProperty("schema_version").GetInt32() == 1, "Fixture schema");
        int cases = 0;
        foreach (JsonElement item in corpus.RootElement.GetProperty("cases").EnumerateArray())
        {
            string name = item.GetProperty("name").GetString()!;
            byte[] raw = Convert.FromHexString(item.GetProperty("wrapper_hex").GetString()!);
            AutoCalHostDirection direction = DirectionForCase(item);
            bool supported = item.GetProperty("framing_supported").GetBoolean();
            AutoCalHostFrame? frame = null;
            try
            {
                frame = AutoCalHostFrame.ParseLongHeader(direction, raw);
            }
            catch (Exception error) when (error is FormatException || error is NotSupportedException)
            {
                Require(!supported, name + ": unexpected rejection: " + error.Message);
            }
            Require((frame != null) == supported, name + ": framing support");
            if (frame != null)
            {
                Require(Hex(frame.RawBytes) == Hex(raw), name + ": original bytes");
                Require(frame.Direction == direction, name + ": direction");
                Require(Hex(frame.OpaqueHeaderBytes) == Hex(raw.AsSpan(2, 8).ToArray()), name + ": opaque header");
                Require(Hex(frame.Payload) == item.GetProperty("payload_hex").GetString(), name + ": payload");
                Require(frame.PayloadLength == frame.Payload.Length, name + ": payload length");
                Require(frame.CrcMatches == item.GetProperty("outer_crc_matches").GetBoolean(), name + ": CRC evidence");
                string? expectedTail = item.GetProperty("rx_trailing_byte_hex").GetString();
                Require(frame.RxTrailingByte?.ToString("x2") == expectedTail, name + ": uninterpreted RX tail");
            }
            cases++;
        }

        CheckByteOwnership();
        CheckLengthBoundaries();
        CheckFailures();
        CheckDirectModelReply();
        Console.WriteLine($"AutoCal offline complete host-frame checks passed: {cases} shared corpus cases, {assertions} assertions.");
        Console.WriteLine("No device, port, DLL loader, or USB stream parser is linked into this harness.");
        return 0;
    }

    private static void CheckByteOwnership()
    {
        byte[] raw = Convert.FromHexString("0152018200000100000005004143563200224819");
        var frame = AutoCalHostFrame.ParseLongHeader(AutoCalHostDirection.DeviceToHost, raw);
        Require(frame.StoredCrc == 0x4822 && frame.ComputedCrc == 0x4822, "CRC little-endian golden");
        raw[0] = 0;
        raw[12] = 0;
        frame.RawBytes[1] = 0;
        frame.OpaqueHeaderBytes[0] = 0;
        frame.Payload[0] = 0;
        Require(Hex(frame.RawBytes) == "0152018200000100000005004143563200224819", "Caller cannot alter retained evidence");
        Require(Hex(frame.OpaqueHeaderBytes) == "0182000001000000", "Opaque bytes are independently owned");
        Require(Hex(frame.Payload) == "4143563200", "Payload bytes are independently owned");
        Require(frame.CrcMatches, "Evidence mutation cannot invalidate stored CRC decision");

        byte[] corrupted = frame.RawBytes;
        corrupted[12] ^= 1;
        var failure = AutoCalHostFrame.ParseLongHeader(AutoCalHostDirection.DeviceToHost, corrupted);
        Require(!failure.CrcMatches, "Corrupted body remains visible as CRC mismatch");
        Require(Hex(failure.RawBytes) == Hex(corrupted), "CRC mismatch does not repair or discard source");
        Require(failure.StoredCrc == 0x4822, "Invalid frame retains original CRC word");
    }

    private static void CheckLengthBoundaries()
    {
        // Exercise the format's uint16 capacity without inventing a valid command.
        foreach (AutoCalHostDirection direction in new[] { AutoCalHostDirection.HostToDevice, AutoCalHostDirection.DeviceToHost })
        foreach (int length in new[] { 0, 255, 256, 65535 })
        {
            bool transmit = direction == AutoCalHostDirection.HostToDevice;
            byte[] raw = new byte[length + (transmit ? 14 : 15)];
            raw[0] = 1;
            raw[1] = transmit ? (byte)0x54 : (byte)0x52;
            raw[10] = (byte)length;
            raw[11] = (byte)(length >> 8);
            if (!transmit) raw[raw.Length - 1] = 0xE7;
            var frame = AutoCalHostFrame.ParseLongHeader(direction, raw);
            Require(frame.PayloadLength == length, "Full uint16 payload length");
            Require(frame.RawBytes.Length == raw.Length, "Exact retained maximum wrapper length");
            if (!transmit) Require(frame.RxTrailingByte == 0xE7, "Arbitrary RX byte retained at length boundary");
            Reject<FormatException>(() => AutoCalHostFrame.ParseLongHeader(direction, raw.AsSpan(0, raw.Length - 1).ToArray()), "One-byte truncation");
            byte[] extra = new byte[raw.Length + 1];
            Array.Copy(raw, extra, raw.Length);
            Reject<FormatException>(() => AutoCalHostFrame.ParseLongHeader(direction, extra), "Extra byte");
        }
    }

    private static void CheckFailures()
    {
        Reject<ArgumentNullException>(() => AutoCalHostFrame.ParseLongHeader(AutoCalHostDirection.HostToDevice, null!), "Null input");
        byte[] tx = Convert.FromHexString("0154018207000000000000008177");
        Reject<NotSupportedException>(() => DirectionForHtxChannel(0), "Unknown HTX channel stays at the container boundary");
        Reject<ArgumentOutOfRangeException>(() => AutoCalHostFrame.ParseLongHeader((AutoCalHostDirection)999, tx), "Invalid direction enum");
        Reject<FormatException>(() => AutoCalHostFrame.ParseLongHeader(AutoCalHostDirection.DeviceToHost, tx), "Mismatched direction");
        for (int length = 0; length < tx.Length; length++)
        {
            int count = length;
            Reject<FormatException>(() => AutoCalHostFrame.ParseLongHeader(AutoCalHostDirection.HostToDevice, tx.AsSpan(0, count).ToArray()), "Truncated complete frame");
        }
        // This is explicitly an unsupported eight-byte header input, not a guessed marker.
        Reject<FormatException>(() => AutoCalHostFrame.ParseLongHeader(AutoCalHostDirection.HostToDevice, tx.AsSpan(0, 8).ToArray()), "Short headers unsupported");
    }

    private static AutoCalHostDirection DirectionForHtxChannel(int channel) => channel switch
    {
        1 => AutoCalHostDirection.HostToDevice,
        2 => AutoCalHostDirection.DeviceToHost,
        _ => throw new NotSupportedException("Only HTX channels 1 and 2 have established directions.")
    };

    private static AutoCalHostDirection DirectionForCase(JsonElement item)
    {
        bool hasChannel = item.TryGetProperty("channel", out JsonElement channel);
        bool hasDirection = item.TryGetProperty("direction", out JsonElement direction);
        if (hasChannel == hasDirection)
            throw new FormatException("A corpus case must supply its actual HTX channel or an explicit direction, never both.");
        if (hasChannel) return DirectionForHtxChannel(channel.GetInt32());
        return direction.GetString() switch
        {
            "host_to_device" => AutoCalHostDirection.HostToDevice,
            "device_to_host" => AutoCalHostDirection.DeviceToHost,
            _ => throw new FormatException("Unknown source direction.")
        };
    }

    private static void CheckDirectModelReply()
    {
        // Complete D2XX response from the independent USB-only model query.
        // It has no HTX channel and no FTDI USB packet-status prefix.
        byte[] reply = Convert.FromHexString("015201820000000000000500414356320026b419");
        var frame = AutoCalHostFrame.ParseLongHeader(AutoCalHostDirection.DeviceToHost, reply);
        Require(frame.CrcMatches && frame.StoredCrc == 0xB426, "Direct model response CRC");
        Require(Hex(frame.Payload) == "4143563200", "Direct response retains ACV2 plus NUL");
        Require(Hex(frame.OpaqueHeaderBytes) == "0182000000000000", "Direct response metadata remains opaque");
        Require(Hex(frame.RawBytes) == Hex(reply), "Direct response bytes are retained without container metadata");
        using var directionCase = JsonDocument.Parse("{\"direction\":\"device_to_host\"}");
        Require(DirectionForCase(directionCase.RootElement) == AutoCalHostDirection.DeviceToHost, "Non-HTX corpus supplies explicit direction");
        using var ambiguous = JsonDocument.Parse("{\"direction\":\"device_to_host\",\"channel\":2}");
        Reject<FormatException>(() => DirectionForCase(ambiguous.RootElement), "Container channel and explicit direction cannot be conflated");
    }

    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    private static void Reject<T>(Action action, string name) where T : Exception
    {
        try { action(); }
        catch (T) { assertions++; return; }
        throw new Exception(name + ": expected " + typeof(T).Name);
    }

    private static void Require(bool condition, string name)
    {
        assertions++;
        if (!condition) throw new Exception(name);
    }
}
