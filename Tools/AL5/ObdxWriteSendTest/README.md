# Offline AL5 writer / production GT integration

This executable uses the production `Vehicle`, `OBDXProDevice` and AL5 dispatcher with a scripted `IPort`. It has no hardware mode, native serial binding or device initialization. Attempts to open/reset/discard the port fail the test.

Basic transport checks:

```powershell
dotnet run --project Tools/AL5/ObdxWriteSendTest/ObdxWriteSendTest.csproj -- --receipt NEW_RECEIPT.json
```

Add explicit local loader/reference files and one or more saved-template/calibration pairs for integration:

```powershell
dotnet run --project Tools/AL5/ObdxWriteSendTest/ObdxWriteSendTest.csproj -- --receipt NEW_RECEIPT.json --al5-writes LOADER.bin FULL_REFERENCE.bin TEMPLATE.txt CALIBRATION.bin
```

Use an ignored LocalOnly receipt path. No download, firmware lookup or live fallback exists. Inputs must fit the pinned selector-zero profile. Full write scenarios select CompleteOfflineRehearsal explicitly; production dispatcher defaults stop before a key submission.

The suite covers short/long DVI packet extents, adapter rejection, malformed/bad-checksum ACKs, bounded silence, queued AL5 replies, full reference rejection by the generic PCM writer, original/custom calibration sessions, boundary stops and failures during upload/erase/program/finalization. A negative send result or post-submission exception remains unknown outcome, with no automatic retry.

Full sessions use saved control/reply stimuli and explicitly omit ambiguous no-reply TX repeats, reporting their count. Readback is a synthetic array reconstructed from serialized wire payloads and modeled erase/marker effects. It establishes host behavior, not physical flashing, wire freshness or recovery. The receipt pins the production library hash and keeps all live-write flags false.
