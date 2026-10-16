# AL5 native boot upload to loader entry and programming

`emulate_boot_loader_handoff.py` closes the earlier software gap between boot
RAM upload and captured-loader entry. Original saved boot code copies the
pinned 1,590-byte loader and calls it through the original JSR. Its entry and
receive/parser/program path then run in the same Unicorn CPU and RAM session.
This is offline software continuity, not a physical controller flash.

The constructor removes the loader bytes initially supplied by the inherited
mapping. All 1,590 offsets must subsequently be written by original boot
instructions during the current attempt, and the resulting SHA-256 must match
before the first uploaded instruction executes. No opcode patch or synthetic
jump replaces the original boot-to-loader call. At handoff, the uploaded page
becomes read-only/executable. A checksum-valid modified kernel fails closed
before executing its first instruction.

Pinned sources are saved LOW editor image SHA-256
`cf5dd139e52ba5925fc95f166627a9a7abcac1374ded8cb738df8297b961a3f6`
and captured loader SHA-256
`b545d9b2d078662466ab32d9cdeb5b3c38c840135e8aeca09f33760ec66780fa`.
They are private source evidence, not current physical backups. The public
`BOOT_LOADER_HANDOFF_EMULATION.json` contains hashes and observations, not the
original loader payload or upload event stream.

## Four same-session sequences

- Native service `0x34` dispatch arms upload and constructs logical reply
  `6D F0 18 74 44`. Native subtype `0x80` upload writes all loader bytes, passes
  the checksum/arming gates and executes the JSR into `0xFF9000`. At that point
  SP is 72 bytes below the synthetic boot stack, with return word `0x33B8`.
  Actual loader entry replaces SP with `0xFFA7FE`, initializes budget `0xFF`
  and reaches receive `0xFF903A`. A later modeled two-word program succeeds
  through the original loader parser/polling/native sender path.
- A bad upload checksum constructs `6C F0 18 76 80 77` and returns through
  the native ISR epilogue without executing the loader, although its bytes
  were already copied. A later valid upload in that same session enters the
  loader; an explicitly modeled program failure retains its pending frame.
- An unarmed upload similarly copies all bytes but rejects at the later
  arming gate and never enters RAM code. Copy completion is insufficient
  evidence of execution authorization.
- Plain subtype `0x00` upload constructs `6C F0 18 76 00 73` and returns
  without executing the loader. This positive RAM-transfer reply must not be
  interpreted as evidence that flash programming occurred.

For the supplied valid upload, actual D7 at loader entry is `0x680`; it remains
that value at first receive because loader entry does not clear it. The native
program routine subsequently clears D7. This replaces the earlier synthetic
entry-register probe with one produced by the original boot transfer code;
it does not establish every possible hardware entry context.

## Scope and verification

Boot interrupt entry and its enable flag are synthetic; peripheral startup,
actual IRQ delivery, exception frames and RTE are omitted. Only a synthetic
idle terminator may remain in the boot queue at handoff; queued data bytes
fail closed. The boot and loader register-event representations do not qualify
a shared physical FIFO. Boot FIFO/send/flush callbacks are guarded synthetic returns. MMIO reads and unexpected writes or
execution fail closed. Watchdog/setup/flash stores remain suppressed. Loader
sender readiness is synthetic and programming supplies readback for two test
words only. There is no native erase effect, whole-image program/readback, or
physical recovery proof. No adapter, driver or vehicle runs.

Ten tests verify zero initial upload bytes, native copy coverage and hash,
real JSR context, stack replacement, inherited D7, checksum retry, rejection
without arming, plain transfer without execution, modified-kernel rejection,
phase/resource/MMIO guards and physical qualification fields. A planner test
hash-links the evidence while physical reset/upload, loader execution,
recovery, automatic retry, live writing and readiness remain unqualified.
The working Mode `$23` reader and C# write gates are unchanged.

With the existing Unicorn 2.1.4 dependency path, `AL5_LOW_DUMP` and
`AL5_CAPTURED_LOADER` set, run from `Tools/AL5`:

```powershell
python -m unittest test_boot_loader_handoff test_offline -q
```

The remaining work includes actual application/session qualification, physical
VPW behavior, erase preservation, independent programmed-image readback and
interrupted-flash recovery. The user currently has no recoverable spare AL5;
the installed TCM remains outside experimental qualification. Live writes
remain disabled.

Validation: **346 offline tests passed with no skips**. The CLI reproduced
the four-case saved report byte-for-byte. Staged changes passed
`git diff --cached --check`; no adapter or controller was accessed.
