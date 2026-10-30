# Offline C-kernel reader verification checks

This harness references the production PcmLibrary project and runs its actual
reader, Vehicle, block parser, CRC verifier and ReadManager against an in-memory
scripted Device. It opens no adapter, port or native library.

```powershell
dotnet build Tools/AL5/CKernelReaderSafetyTest/CKernelReaderSafetyTest.csproj -c Release /p:GeneratePackageOnBuild=false
dotnet LocalOnly/CKernelReaderSafetyTest/bin/CKernelReaderSafetyTest.dll --receipt LocalOnly/CKernelReaderSafetyTest/results.json
```

Use a new receipt path. Fixtures generate a synthetic 512KiB image and a 16-byte
zero stub under unique test-output directories. The stub only exercises host
upload framing and is never executed. Fixture files are removed individually;
the empty owned directory is then removed without recursive deletion.

Cases cover all seven CRC ranges after 128 actual parsed blocks, mismatch,
timeout salvage, cancellation during and with the final CRC, unknown verifier
results, cancellation during the last block, missing or corrupt block replies,
and ReadManager's normal/no-file/`_badread` behavior. A narrow CompareRanges
override supplies only otherwise unreachable result contracts. Existing reader
cleanup runs through the fake Device; this does not qualify physical cleanup,
AutoCal transport, kernel execution, flash programming or recovery.
