# C-kernel writer safety tests

This developer executable exercises the current checkout's production
`CKernelWriter` and `WriteManager` with a scripted in-memory `Device`. It has no
hardware mode, native USB binding, serial port or controller connection.

From the repository root:

```powershell
dotnet build Tools/AL5/CKernelWriterSafetyTest/CKernelWriterSafetyTest.csproj -c Release /p:GeneratePackageOnBuild=false
dotnet LocalOnly/CKernelWriterSafetyTest/bin/CKernelWriterSafetyTest.dll --receipt LocalOnly/CKernelWriterSafetyTest/results.json
```

The receipt path must be new. Build products and receipts stay under ignored
`LocalOnly/CKernelWriterSafetyTest/`. Each receipt records the tested production
library hash and individual results. A failure returns exit code 1.

The 26 cases cover current CRC verification, verification after the fifth write
pass, cancellation, timeout, erase/program errors, OS and image-size guards,
existing and freshly uploaded kernel states, E54 failure cleanup, non-E54
controls, Compare/TestWrite and AL5 rejection before device access. One test
runs all 96 calibration packets through production `Vehicle.WritePayload` and
validates their addresses and payload bytes. Other cases use the narrow
`CompareRanges` or `WriteMemoryRange` overrides to inject otherwise unreachable
result contracts or avoid repeating the same block transfer during retries.
These overrides do not replace the production write/verify loop.

The manager test generates a synthetic image that passes `FileValidator`, takes
the existing-kernel path and reaches a real verifier timeout, then asserts that
`WriteManager` returns the writer's failure. The AL5 test rejects a segment-sized
array before the scripted device receives any message.

Fresh-kernel cases create a temporary 16-byte zero-filled stub under the test
output directory, pass it through the mocked upload exchange, then delete that
single file and its empty directory. The stub is not executable firmware; the
fake device does not execute bytes. No stock or custom tune is read or retained.

These are bounded host-orchestration tests, not the complete legacy test suite.
They do not qualify an AutoCal backend, physical flashing, bus timing, or
interrupted-flash recovery. They add no force option and do not enable AL5 writes.
