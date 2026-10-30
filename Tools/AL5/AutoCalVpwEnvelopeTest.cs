// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using PcmHacking;

internal static class AutoCalVpwEnvelopeTest
{
    private const AutoCalVpwRequestContext Context = AutoCalVpwRequestContext.ExplicitVpwRequest8A00Context;
    private static int assertions;

    public static int Main(string[] args)
    {
        if (args.Length > 1) throw new ArgumentException("Expected at most one private saved-corpus path.");
        Boundaries();
        int cases = args.Length == 1 ? SavedCorpus(args[0]) : 0;
        Console.WriteLine(JsonSerializer.Serialize(new {
            assertions, savedCases = cases, adapterOpened = false, liveWriteEnabled = false,
            pcmLibraryAssembly = typeof(AutoCalVpwEnvelope).Assembly.Location,
            scope = "Offline host-field projection under supplied context; no request pairing or physical validation"
        }));
        return 0;
    }

    private static void Boundaries()
    {
        Throws<ArgumentNullException>(() => AutoCalVpwEnvelope.Project(null!, Context), "null frame");
        byte[] body = Convert.FromHexString("6C10F023010203");
        var txFrame = Frame(AutoCalHostDirection.HostToDevice, "008A0700785634F2", body);
        foreach (var context in new[] { AutoCalVpwRequestContext.Unspecified, (AutoCalVpwRequestContext)99 })
        {
            var absent = AutoCalVpwEnvelope.Project(txFrame, context);
            Require(absent.Kind == AutoCalVpwProjectionKind.UnsupportedContext, "explicit supported context required");
            Require(absent.HostBusPayload == null, "no bus projection without context");
            Same(txFrame.RawBytes, absent.RawFrame, "unsupported context retains frame");
        }
        var tx = AutoCalVpwEnvelope.Project(txFrame, Context);
        Require(tx.Kind == AutoCalVpwProjectionKind.TransmitCommand, "TX command");
        Require(tx.TransmitCommandWord == 0x8A00 && tx.TransmitSelectorByte == 7 && tx.TransmitReservedByte == 0, "TX fields");
        Require(tx.TransmitCallerMetadata == 0xF2345678U, "TX metadata little endian including high bit");
        Require(tx.ReceiveReturnedMetadata == null && tx.ExceptionStatus == null, "TX does not expose RX/status");
        Same(body, tx.HostBusPayload!, "TX retains entire body");
        tx.HostBusPayload![0] ^= 0xff;
        tx.RawPayload[0] ^= 0xff;
        tx.RawFrame[0] ^= 0xff;
        Same(body, tx.HostBusPayload!, "returned arrays are defensive copies");
        Same(txFrame.RawBytes, tx.RawFrame, "raw frame remains immutable");

        var local = AutoCalVpwEnvelope.Project(Frame(AutoCalHostDirection.HostToDevice, "0182070000000000", body), Context);
        Require(local.Kind == AutoCalVpwProjectionKind.TransmitCommandMismatch && local.HostBusPayload == null,
            "local command containing VPW-looking bytes is not bus data");
        Same(body, local.RawPayload, "mismatch raw bytes retained");

        // The explicit context, not RX bytes 2..3 or a payload prefix, selects interpretation.
        var rxFrame = Frame(AutoCalHostDirection.DeviceToHost, "030201C089ABCDEF", body);
        var rx = AutoCalVpwEnvelope.Project(rxFrame, Context);
        Require(rx.Kind == AutoCalVpwProjectionKind.ReceivePayload && rx.ReceiveReturnedMetadata == 0xC0010203U, "unknown RX metadata retained");
        Same(Convert.FromHexString("89ABCDEF"), rx.ReceiveOpaqueHeader6To9!, "RX opaque DWORD");
        rx.ReceiveOpaqueHeader6To9![0] ^= 0xff;
        Same(Convert.FromHexString("89ABCDEF"), rx.ReceiveOpaqueHeader6To9!, "opaque header copy");
        Same(body, rx.HostBusPayload!, "RX body unchanged");
        Require(rx.TransmitCallerMetadata == null && rx.ExceptionStatus == null, "RX metadata is not exception status");
        var localRx = Frame(AutoCalHostDirection.DeviceToHost, "0182000000000000", Convert.FromHexString("4143563200"));
        Require(AutoCalVpwEnvelope.Project(localRx, AutoCalVpwRequestContext.Unspecified).HostBusPayload == null,
            "model reply is not auto-dispatched");
        // Deliberately supplying the wrong context cannot be detected from an RX frame.
        Require(AutoCalVpwEnvelope.Project(localRx, Context).ReceiveReturnedMetadata == 0x8201,
            "caller assumption is not a recovered request identity");

        foreach (var direction in new[] { AutoCalHostDirection.HostToDevice, AutoCalHostDirection.DeviceToHost })
        {
            byte[] raw = Frame(direction, direction == AutoCalHostDirection.HostToDevice ? "008A070010000000" : "1000000000000000", body).RawBytes;
            raw[12 + body.Length] ^= 1;
            var corrupt = AutoCalVpwEnvelope.Project(AutoCalHostFrame.ParseLongHeader(direction, raw), Context);
            Require(corrupt.Kind == AutoCalVpwProjectionKind.InvalidOuterCrc && !corrupt.OuterCrcMatches, "CRC failure rejected");
            Require(corrupt.HostBusPayload == null && corrupt.ReceiveReturnedMetadata == null, "CRC failure has no accepted fields");
            Same(raw, corrupt.RawFrame, "CRC failure evidence retained");
        }

        foreach (int length in new[] { 0, 1, 0xC000, 0xC001, 0xFFFF })
        {
            var projected = AutoCalVpwEnvelope.Project(Frame(AutoCalHostDirection.DeviceToHost, "1000000000000000", new byte[length]), Context);
            Require(projected.Kind == (length > 0xC000 ? AutoCalVpwProjectionKind.UnsupportedReceivePayloadLength : AutoCalVpwProjectionKind.ReceivePayload), "native RX length boundary");
            Require(projected.RawPayload.Length == length, "rejected length retains bytes");
        }
        Require(AutoCalVpwEnvelope.Project(Frame(AutoCalHostDirection.HostToDevice, "008A070000000000", new byte[0xC001]), Context).Kind == AutoCalVpwProjectionKind.TransmitCommand,
            "RX cap is not invented as a TX restriction");

        for (int length = 0; length < 4; length++)
        {
            var malformed = Error(new byte[length]);
            Require(malformed.Kind == AutoCalVpwProjectionKind.MalformedCommandError, "short error payload retained as malformed");
            Require(malformed.HostBusPayload == null && malformed.ReceiveReturnedMetadata == null && malformed.ExceptionStatus == null, "short error cannot become bus/status");
        }
        var error = Error(Convert.FromHexString("008A3605AABB"));
        Require(error.Kind == AutoCalVpwProjectionKind.CommandError && error.ErrorEchoedCommand == 0x8A00 && error.ErrorEchoMatchesRequestedCommand == true, "error command echo");
        Require(error.ExceptionStatus == 0x0536 && error.HostBusPayload == null && error.ReceiveReturnedMetadata == null, "error status distinct from bus metadata");
        Same(Convert.FromHexString("AABB"), error.ErrorTrailingPayload!, "uninterpreted error remainder");
        error.ErrorTrailingPayload![0] ^= 0xff;
        Same(Convert.FromHexString("AABB"), error.ErrorTrailingPayload!, "error remainder copy");
        var mismatch = Error(Convert.FromHexString("01823605"));
        Require(mismatch.Kind == AutoCalVpwProjectionKind.ErrorCommandMismatch && mismatch.ErrorEchoMatchesRequestedCommand == false, "echo mismatch rejected");
        Require(mismatch.ExceptionStatus == null && mismatch.HostBusPayload == null, "mismatched status not attributed to request");
        Same(Convert.FromHexString("01823605"), mismatch.RawPayload, "mismatched status still retained raw");
    }

    private static int SavedCorpus(string path)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(path));
        var root = document.RootElement;
        Require(root.GetProperty("schema_version").GetInt32() == 1, "private corpus schema");
        Require(root.GetProperty("rx_context_assumed_for_projection_tests").GetBoolean(), "RX context assumption remains explicit");
        Require(!root.GetProperty("rx_request_pairing_established").GetBoolean() && !root.GetProperty("physical_protocol_validation").GetBoolean(), "corpus is not physical validation");
        int count = 0, txCount = 0, rxCount = 0;
        foreach (var item in root.GetProperty("cases").EnumerateArray())
        {
            bool isTx = item.GetProperty("direction").GetString() == "host_to_device";
            Require(isTx || item.GetProperty("direction").GetString() == "device_to_host", "explicit corpus direction");
            Require(item.GetProperty("requested_command_context").GetString() == "0x8A00", "supplied profile");
            Require(item.GetProperty("context_independently_established_from_this_record").GetBoolean() == isTx, "no invented RX context");
            byte[] bytes = Convert.FromHexString(item.GetProperty("wrapper_hex").GetString()!);
            Require(Hash(bytes) == item.GetProperty("wrapper_sha256").GetString(), "corpus frame digest");
            var frame = AutoCalHostFrame.ParseLongHeader(isTx ? AutoCalHostDirection.HostToDevice : AutoCalHostDirection.DeviceToHost, bytes);
            var projection = AutoCalVpwEnvelope.Project(frame, Context);
            Require(projection.OuterCrcMatches == item.GetProperty("outer_crc_matches").GetBoolean(), "saved outer CRC");
            Require(projection.Kind == (isTx ? AutoCalVpwProjectionKind.TransmitCommand : AutoCalVpwProjectionKind.ReceivePayload), "saved normal projection");
            Require(projection.RawPayload.Length == item.GetProperty("payload_bytes").GetInt32(), "saved payload extent");
            Require(Hash(projection.HostBusPayload!) == item.GetProperty("payload_sha256").GetString(), "saved payload unchanged");
            if (isTx)
            {
                txCount++;
                Require(projection.TransmitSelectorByte == item.GetProperty("expected_tx_selector_byte").GetByte(), "saved selector");
                Require(projection.TransmitReservedByte == item.GetProperty("expected_tx_reserved_byte").GetByte(), "saved reserved");
                Require(projection.TransmitCallerMetadata == item.GetProperty("expected_tx_caller_metadata_le32").GetUInt32(), "saved TX metadata");
            }
            else
            {
                rxCount++;
                Require(projection.ReceiveReturnedMetadata == item.GetProperty("expected_rx_returned_metadata_le32").GetUInt32(), "saved RX metadata");
                Same(Convert.FromHexString(item.GetProperty("expected_rx_opaque_header_6_9_hex").GetString()!), projection.ReceiveOpaqueHeader6To9!, "saved opaque bytes");
            }
            count++;
        }
        Require(txCount == root.GetProperty("transmit_cases").GetInt32() && rxCount == root.GetProperty("receive_cases").GetInt32(), "corpus direction coverage");
        Require(count != 0, "nonempty corpus");
        return count;
    }

    private static AutoCalVpwEnvelope Error(byte[] payload)
        => AutoCalVpwEnvelope.Project(Frame(AutoCalHostDirection.DeviceToHost, "00FFABCD11223344", payload), Context);

    private static AutoCalHostFrame Frame(AutoCalHostDirection direction, string headerHex, byte[] payload)
    {
        byte[] bytes = new byte[12 + payload.Length + 2 + (direction == AutoCalHostDirection.DeviceToHost ? 1 : 0)];
        bytes[0] = 1; bytes[1] = direction == AutoCalHostDirection.HostToDevice ? (byte)0x54 : (byte)0x52;
        Convert.FromHexString(headerHex).CopyTo(bytes, 2);
        bytes[10] = (byte)payload.Length; bytes[11] = (byte)(payload.Length >> 8);
        payload.CopyTo(bytes, 12);
        ushort crc = 0;
        for (int i = 0; i < 12 + payload.Length; i++)
        {
            crc ^= bytes[i];
            for (int bit = 0; bit < 8; bit++) crc = (ushort)((crc >> 1) ^ ((crc & 1) != 0 ? 0xA001 : 0));
        }
        bytes[12 + payload.Length] = (byte)crc; bytes[13 + payload.Length] = (byte)(crc >> 8);
        if (direction == AutoCalHostDirection.DeviceToHost) bytes[^1] = 0x19;
        return AutoCalHostFrame.ParseLongHeader(direction, bytes);
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
