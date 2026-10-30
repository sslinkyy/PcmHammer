// SPDX-License-Identifier: GPL-3.0-only
using PcmHacking;

// Exact, closed profiles. This developer tool cannot accept arbitrary commands,
// tune files, addresses, retry counts, unlocks, speed changes or kernel uploads.
internal sealed class ProbeProfile
{
    public bool ReadsE54Identity { get; }
    public string Name => ReadsE54Identity ? "e54-osid-read" : "usb-setup";
    public AutoCalSetupProfile Setup => ReadsE54Identity
        ? AutoCalSetupProfile.RecordedOrdinaryIdentification : AutoCalSetupProfile.RecordedE54Read;
    public const uint ExpectedOperatingSystem = 15189044;
    readonly byte[][] requests;
    public byte[][] Requests => requests.Select(x => (byte[])x.Clone()).ToArray();
    public byte[] OsRequest => Convert.FromHexString("6C10F03C0A");
    public ProbeProfile(bool readsE54Identity)
    {
        ReadsE54Identity = readsE54Identity;
        var requests = new List<byte[]> {
            Frame(0x8201, ""), Frame(0x8604, "00"), Frame(0x8800, "0000") };
        if (readsE54Identity)
        {
            requests.Add(Frame(0x8604, "000000000000"));
            requests.Add(AutoCalHostFrame.EncodeLongHeader(0x8A00, 7, 0x10, OsRequest));
        }
        else
        {
            requests.Add(Frame(0x8603, "0100F401"));
            requests.Add(Frame(0x8604, "010010000000"));
        }
        requests.Add(Frame(0x8604, "000000000000"));
        requests.Add(Frame(0x8B01, "00010000"));
        requests.Add(Frame(0x8B01, "01010000"));
        this.requests = requests.ToArray();
    }
    static byte[] Frame(ushort command, string payload)
        => AutoCalHostFrame.EncodeLongHeader(command, 7, 0, Convert.FromHexString(payload));

    public Message CreateOsRequest()
    {
        var request = new Protocol().CreateOperatingSystemIdReadRequest();
        if (!ReadsE54Identity || !request.GetBytes().SequenceEqual(OsRequest))
            throw new InvalidOperationException("PcmHammer's request differs from the fixed read-only profile.");
        return request;
    }

    public uint? ParseIdentity(byte[] bytes)
    {
        // Reject negative responses for this tester/controller pair. Preserve
        // unrelated traffic in the journal but never treat it as an OS reply.
        if (bytes.Length >= 5 && bytes.AsSpan(0, 5).SequenceEqual(Convert.FromHexString("6CF0107F3C")))
            throw new InvalidDataException("E54 rejected the read-block request: " + Convert.ToHexString(bytes));
        if (bytes.Length < 5 || !bytes.AsSpan(0, 5).SequenceEqual(Convert.FromHexString("6CF0107C0A"))) return null;
        // Observed replies: 11 bytes during read-12 ordinary identification,
        // 9 bytes in the later failed-write session. The suffix remains opaque.
        if (bytes.Length != 9 && bytes.Length != 11)
            throw new InvalidDataException("OS-ID reply has an unobserved extent: " + Convert.ToHexString(bytes));
        var result = new Protocol().ParseUInt32FromBlockReadResponse(new Message(bytes));
        if (result.Status != ResponseStatus.Success || result.Value != ExpectedOperatingSystem)
            throw new InvalidDataException("OS-ID does not match the isolated E54 baseline: " + Convert.ToHexString(bytes));
        return result.Value;
    }
}

internal sealed class ExactRequestGuard
{
    readonly byte[][] requests;
    byte[]? current;
    int offset;
    bool pending;
    public int CommandsStarted { get; private set; }
    public int VpwPayloadCommandsStarted { get; private set; }
    public int VpwPayloadCommandsCompleted { get; private set; }
    public ExactRequestGuard(ProbeProfile profile)
        => requests = profile.Requests.Select(x => (byte[])x.Clone()).ToArray();

    public void BeforeWrite(byte[] bytes, int at, int count)
    {
        if (pending) throw new InvalidOperationException("Concurrent or uncertain write cannot be replayed.");
        if (current == null || offset == current.Length)
        {
            if (CommandsStarted >= requests.Length || at != 0 || count != bytes.Length
                || !bytes.SequenceEqual(requests[CommandsStarted]))
                throw new InvalidOperationException("Request differs from the exact fixed sequence.");
            current = (byte[])bytes.Clone(); offset = 0; CommandsStarted++;
            if (current[2] == 0 && current[3] == 0x8A) VpwPayloadCommandsStarted++;
        }
        if (current == null || at != offset || count != current.Length - offset || !bytes.SequenceEqual(current))
            throw new InvalidOperationException("Partial write is not the exact remaining suffix.");
        pending = true;
    }

    public void CompleteWrite(int returned)
    {
        if (!pending || current == null || returned < 0 || returned > current.Length - offset)
            throw new InvalidOperationException("Native completion cannot be reconciled with the pending write.");
        offset += returned; pending = false;
        if (offset == current.Length && current[2] == 0 && current[3] == 0x8A) VpwPayloadCommandsCompleted++;
    }
}
