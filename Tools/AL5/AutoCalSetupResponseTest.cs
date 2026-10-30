// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using PcmHacking;

internal static class AutoCalSetupResponseTest
{
    private static int assertions;
    private static readonly AutoCalSetupCommandContext[] Contexts = {
        AutoCalSetupCommandContext.Command8603, AutoCalSetupCommandContext.Command8604,
        AutoCalSetupCommandContext.Command8800, AutoCalSetupCommandContext.Command8B01
    };

    public static int Main(string[] args)
    {
        if (args.Length > 1) throw new ArgumentException("Expected at most one private saved-corpus path.");
        Boundaries();
        int savedCases = args.Length == 1 ? SavedCorpus(args[0]) : 0;
        Console.WriteLine(JsonSerializer.Serialize(new {
            assertions, savedCases, adapterOpened = false, liveWriteEnabled = false,
            pcmLibraryAssembly = typeof(AutoCalSetupResponse).Assembly.Location,
            scope = "Offline setup response projection; command context supplied, no transaction pairing or firmware qualification"
        }));
        return 0;
    }

    private static void Boundaries()
    {
        var context = AutoCalSetupCommandContext.Command8604;
        Throws<ArgumentNullException>(() => AutoCalSetupResponse.Project(null!, context), "null frame");
        var normalFrame = Frame(0x8604, new byte[] { 1 });
        foreach (var invalid in new[] { AutoCalSetupCommandContext.Unspecified, (AutoCalSetupCommandContext)0x8A00 })
        {
            var rejected = AutoCalSetupResponse.Project(normalFrame, invalid);
            Require(rejected.Kind == AutoCalSetupResponseKind.UnsupportedContext, "explicit supported context required");
            Require(rejected.ReplyPayload == null && rejected.ReceivedCommandWord == null, "no interpretation without context");
            Same(normalFrame.RawBytes, rejected.RawFrame, "unsupported context retains bytes");
        }
        var tx = AutoCalSetupResponse.Project(Frame(0x8604, new byte[] { 1 }, true), context);
        Require(tx.Kind == AutoCalSetupResponseKind.UnsupportedDirection && tx.ReplyPayload == null,
            "echoing request cannot substitute for a response");

        foreach (var selected in Contexts)
        {
            foreach (byte[] payload in new[] { Array.Empty<byte>(), new byte[] { 0 }, new byte[] { 1 }, new byte[] { 0xff, 0, 1 } })
            {
                var normal = AutoCalSetupResponse.Project(Frame((ushort)selected, payload), selected);
                Require(normal.Kind == AutoCalSetupResponseKind.EchoedCommandResponse, "matching normal envelope");
                Require(normal.ReturnedPayloadLength == payload.Length, "length is authoritative even when zero");
                Same(payload, normal.ReplyPayload!, "no status byte interpretation or stripping");
                Require(normal.ExceptionStatus == null && normal.ErrorEchoedCommand == null, "normal body is not an error status");
            }
            foreach (var other in Contexts.Where(c => c != selected))
            {
                var wrong = AutoCalSetupResponse.Project(Frame((ushort)other, new byte[] { 1 }), selected);
                Require(wrong.Kind == AutoCalSetupResponseKind.ResponseCommandMismatch, "different local reply rejected");
                Require(wrong.ReplyPayload == null && wrong.ReturnedPayloadLength == null, "mismatch is not an empty response");
                Require(wrong.ReceivedCommandWord == (ushort)other, "mismatched command preserved");
            }
        }

        var immutable = AutoCalSetupResponse.Project(normalFrame, context);
        byte[] originalRaw = immutable.RawFrame;
        immutable.RawFrame[0] ^= 0xff;
        immutable.RawPayload[0] ^= 0xff;
        immutable.ReplyPayload![0] ^= 0xff;
        immutable.OpaqueHeader4To9![0] ^= 0xff;
        Same(originalRaw, immutable.RawFrame, "raw immutable");
        Same(new byte[] { 1 }, immutable.ReplyPayload!, "payload immutable");
        Same(Convert.FromHexString("A1B2C3D4E5F6"), immutable.OpaqueHeader4To9!, "all six opaque bytes retained and immutable");

        byte[] corrupt = normalFrame.RawBytes;
        corrupt[corrupt.Length - 3] ^= 1;
        var badCrc = AutoCalSetupResponse.Project(AutoCalHostFrame.ParseLongHeader(AutoCalHostDirection.DeviceToHost, corrupt), context);
        Require(badCrc.Kind == AutoCalSetupResponseKind.InvalidOuterCrc, "CRC precedes field interpretation");
        Require(badCrc.ReplyPayload == null && badCrc.ReceivedCommandWord == null, "CRC cannot become a reply");
        Same(corrupt, badCrc.RawFrame, "CRC failure retained");

        foreach (int length in new[] { 0xC000, 0xC001, 0xFFFF })
        {
            var bounded = AutoCalSetupResponse.Project(Frame(0x8604, new byte[length]), context);
            Require(bounded.Kind == (length <= 0xC000 ? AutoCalSetupResponseKind.EchoedCommandResponse
                : AutoCalSetupResponseKind.UnsupportedReceivePayloadLength), "native receive capacity boundary");
            Require(bounded.RawPayload.Length == length, "oversized evidence retained");
        }
        for (int length = 0; length < 4; length++)
        {
            var malformed = AutoCalSetupResponse.Project(Frame(0xFF00, new byte[length]), context);
            Require(malformed.Kind == AutoCalSetupResponseKind.MalformedCommandError, "short error cannot become a normal reply");
            Require(malformed.ExceptionStatus == null && malformed.ReplyPayload == null, "short error has no accepted status or body");
        }
        foreach (ushort status in new ushort[] { 0, 0x0536, 0xFFFF })
        {
            var error = AutoCalSetupResponse.Project(Frame(0xFF00, new byte[] { 4, 0x86, (byte)status, (byte)(status >> 8), 0xAB, 0xCD }), context);
            Require(error.Kind == AutoCalSetupResponseKind.CommandError && error.ExceptionStatus == status,
                "error marker remains failure even for zero status");
            Require(error.ErrorEchoMatchesRequestedCommand == true && error.ErrorEchoedCommand == 0x8604, "error echo matches context");
            Require(error.ReturnedPayloadLength == null && error.ReplyPayload == null, "error not accepted as reply");
            error.ErrorTrailingPayload![0] ^= 0xff;
            Same(new byte[] { 0xAB, 0xCD }, error.ErrorTrailingPayload!, "error trailing evidence immutable");
        }
        var mismatchedError = AutoCalSetupResponse.Project(Frame(0xFF00, new byte[] { 3, 0x86, 0x36, 5 }), context);
        Require(mismatchedError.Kind == AutoCalSetupResponseKind.ErrorCommandMismatch && mismatchedError.ErrorEchoMatchesRequestedCommand == false,
            "error echo mismatch rejected");
        Require(mismatchedError.ExceptionStatus == null && mismatchedError.ReplyPayload == null, "foreign error is not attributed to supplied request");
        Same(new byte[] { 3, 0x86, 0x36, 5 }, mismatchedError.RawPayload, "foreign status retained raw");

        var bus = AutoCalSetupResponse.Project(Frame(0x0010, Convert.FromHexString("6CF010E0AA")), context);
        Require(bus.Kind == AutoCalSetupResponseKind.ResponseCommandMismatch && bus.ReplyPayload == null,
            "bus metadata and VPW-looking payload do not select setup semantics");
    }

    private static int SavedCorpus(string path)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(path));
        var root = document.RootElement;
        Require(root.GetProperty("schema_version").GetInt32() == 1, "saved corpus schema");
        Require(root.GetProperty("rx_context_assumed_for_projection_tests").GetBoolean(), "offline context assumption explicit");
        Require(!root.GetProperty("rx_request_pairing_established").GetBoolean()
            && !root.GetProperty("physical_protocol_validation").GetBoolean(), "saved corpus does not establish pairing or physical behavior");
        int count = 0;
        foreach (var item in root.GetProperty("cases").EnumerateArray())
        {
            Require(item.GetProperty("direction").GetString() == "device_to_host", "RX corpus only");
            ushort command = Convert.ToUInt16(item.GetProperty("requested_command_context").GetString()!.Substring(2), 16);
            Require(Contexts.Contains((AutoCalSetupCommandContext)command), "supported supplied context");
            byte[] raw = Convert.FromHexString(item.GetProperty("wrapper_hex").GetString()!);
            Require(Hash(raw) == item.GetProperty("wrapper_sha256").GetString(), "saved frame digest");
            var result = AutoCalSetupResponse.Project(AutoCalHostFrame.ParseLongHeader(AutoCalHostDirection.DeviceToHost, raw),
                (AutoCalSetupCommandContext)command);
            Require(result.Kind == AutoCalSetupResponseKind.EchoedCommandResponse, "saved normal reply envelope");
            Require(result.OuterCrcMatches && item.GetProperty("outer_crc_matches").GetBoolean(), "saved CRC");
            Require(result.ReturnedPayloadLength == item.GetProperty("payload_bytes").GetInt32(), "saved payload extent");
            Require(Hash(result.ReplyPayload!) == item.GetProperty("payload_sha256").GetString(), "saved payload unchanged");
            Same(Convert.FromHexString(item.GetProperty("opaque_header_4_9_hex").GetString()!), result.OpaqueHeader4To9!, "saved opaque header");
            count++;
        }
        Require(count > 0 && count == root.GetProperty("receive_cases").GetInt32(), "nonempty saved corpus coverage");
        return count;
    }

    private static AutoCalHostFrame Frame(ushort command, byte[] payload, bool tx = false)
    {
        byte[] bytes = new byte[12 + payload.Length + 2 + (tx ? 0 : 1)];
        bytes[0] = 1; bytes[1] = tx ? (byte)0x54 : (byte)0x52;
        bytes[2] = (byte)command; bytes[3] = (byte)(command >> 8);
        Convert.FromHexString("A1B2C3D4E5F6").CopyTo(bytes, 4);
        bytes[10] = (byte)payload.Length; bytes[11] = (byte)(payload.Length >> 8);
        payload.CopyTo(bytes, 12);
        ushort crc = 0;
        for (int i = 0; i < 12 + payload.Length; i++)
        {
            crc ^= bytes[i];
            for (int bit = 0; bit < 8; bit++) crc = (ushort)((crc >> 1) ^ ((crc & 1) != 0 ? 0xA001 : 0));
        }
        bytes[12 + payload.Length] = (byte)crc; bytes[13 + payload.Length] = (byte)(crc >> 8);
        if (!tx) bytes[^1] = 0x19;
        return AutoCalHostFrame.ParseLongHeader(tx ? AutoCalHostDirection.HostToDevice : AutoCalHostDirection.DeviceToHost, bytes);
    }

    private static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    private static void Same(byte[] expected, byte[] actual, string reason) => Require(expected.SequenceEqual(actual), reason);
    private static void Require(bool condition, string reason)
    {
        assertions++;
        if (!condition) throw new InvalidOperationException(reason);
    }
    private static void Throws<T>(Action action, string reason) where T : Exception
    {
        try { action(); } catch (T) { assertions++; return; }
        throw new InvalidOperationException(reason + ": expected " + typeof(T).Name);
    }
}
