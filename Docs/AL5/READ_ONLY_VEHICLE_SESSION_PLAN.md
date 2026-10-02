# Next AL5 vehicle session: listen, identify, read, compare

Prepared 2026-10-02 for the user's only installed TCM. OBDX Pro GT is available;
the truck is currently unavailable. AutoCal V2 is also available, but it is not
part of this session. This is a preparation plan, not a claim that passive
capture or an identity-only mode is already implemented.

## Purpose and scope

Obtain a reproducible current calibration baseline and bounded observations of
normal VPW traffic. Discoveries guide subsequent offline analysis. This session
does not qualify a writer, prove recovery or obtain all collateral-region backups.

The only planned TCM requests are previously demonstrated Mode 0x3C identity
blocks 0x08 and 0x0A, and the existing Mode 0x23 calibration reader over
0x08000–0x15FD7, including its existing 0x158A8 anchor preflight. Use normal VPW
1X throughout. No address sweep, arbitrary service/subtype sweep, security seed
or key request, programming-session entry, RAM upload/execution, erase/program,
reset request, fault clearing or speed-change request belongs in this session.
Normal ignition operation is not a diagnostic reset service; keep ignition on
and stable throughout each capture/read.

## Preparation before the truck returns

1. Preserve the current working branch and known direct-reader build. Record the
   exact Git commit and executable hash used in the session. Do not change the
   AL5 reader or unconditional shared-writer rejection merely to add listening.
2. Prepare a separate bounded passive capture path for the OBDX Pro GT. The
   current adapter initialization enables the network and filters destination
   F0; that is not an all-traffic listening mode. Verify the manufacturer's
   adapter-local receive/filter controls and transmit inhibition before using
   them. Do not guess command semantics from a constant name. Confirm that
   capture/start/stop cannot call the vehicle-message transmitter. Account for
   startup, cancellation, timeout and cleanup, not only the receive loop.
3. Prepare a dedicated identity-only path limited to the two demonstrated blocks.
   The current `AL5 Read-Only Identity Probe...` action additionally requests a
   security seed and tests memory addresses. Its identity-only dialog description
   is incomplete. Do not use that action for this narrower plan until a separate
   path is ready. Do not change or expand the legacy probe's behavior silently.
4. Validate new paths offline with a fake adapter/transport: reject all vehicle
   sends during passive capture, permit only the exact identity allowlist in the
   identity stage, enforce bounded duration/counts, and verify cancellation and
   unexpected-response behavior. Build the application and repeat the existing
   write-rejection harness if C# changes are made. Passing fake tests is not
   physical adapter qualification.
5. Set up an ignored `LocalOnly/AL5/Sessions/<session-id>/` output directory with
   separate passive captures, raw identity logs, two calibration BINs and a
   manifest. Preserve original logs with identifiers privately. Git may contain
   redacted findings, counts and hashes, never VIN/serial, private payloads or BINs.

The normal direct-read stage can still proceed if the optional passive/identity
paths are not ready. Skip those stages rather than improvise adapter commands
or substitute the broader legacy probe.

## At the truck

Allow an uninterrupted session with enough time for two reads, each potentially
several minutes. Park, secure the vehicle and leave the engine off. Use stable
battery power suitable for a diagnostic session. Confirm the adapter-reported
voltage is stable; a model-specific acceptable range must come from applicable
equipment documentation, not an invented generic threshold. Stop if power or
communication becomes unstable.

Connect only OBDX Pro GT for this session. Close competing serial/J2534 tools;
disconnect AutoCal from the diagnostic port. Confirm the current adapter model
and port rather than assuming historical COM9 is still correct. Record connection
type, software/build, adapter firmware, ignition/engine state and power conditions.
Record any warnings already present before the session. Do not clear them.

### Stage A — optional passive baseline, 120 seconds

Only use the separately verified receive-only path. Capture a fixed 120-second
window at 1X with zero vehicle-message transmissions. Record host timestamps,
raw received frames privately, adapter errors/drops/CRC policy and source/destination
counts where framing is established. Host timestamps are not wire timing proof.
Attribute a message to the TCM only when its source addressing is established;
ordinary bus traffic includes other modules.

No traffic is a valid observation. Check the receive configuration offline; do
not wake modules with speculative requests or interpret silence as a dead TCM.

### Stage B — optional bounded known identities

Use the separate identity-only path. Request block 0x08 once, then block 0x0A
once. After those complete, allow one repeat of each for consistency: four
requests maximum, sequentially, with no automatic scan or alternative subtypes.
Log full replies privately, including negative/timeout/unexpected results.

Previously observed block 0x08 carries hardware 15183963; block 0x0A carries OS
15184109. Preserve raw block semantics rather than borrowing generic PCM labels.
If either identity differs, stop the active portion and analyze that target
offline before applying this OS-specific reader/anchor interpretation.

### Stage C — two existing direct calibration reads

Use `Tools -> AL5 Read Calibration...`, not the broader identity-probe menu item.
Save the first completed, validated read as `calibration_A.bin` and its debug log.
Keep the ignition and connection unchanged. After a short idle pause, perform
the same read again and save `calibration_B.bin` with its own log. Do not edit,
checksum-correct or overwrite either original.

Both must be exactly 57,304 bytes. Require the reader's anchor checks, zero BE16
sum and independent native four-byte checksum validation. The UI can save a
result labeled `Unverified`; saving it does not make it a valid baseline. Keep
such a file for diagnosis only and stop rather than proceeding as if validated.

### Stage D — optional passive closing window, 60 seconds

With the same verified passive path, capture another fixed minute after reads.
Compare message counts and visible communication behavior with Stage A. Quietness
or a changed traffic rate is not proof of unchanged persistent records or safe
programming. Do not clear faults or perform actuator/road tests in this session.

## Offline acceptance and outputs

Compare A and B byte for byte and by SHA256. Hash equality establishes repeatable
calibration content for that session, not whole-module integrity. Validate native
checksums using `Tools/AL5/checksum.py <BIN>` without `--output`; it reports only
and does not modify the file. Retain a manifest binding both BINs, logs, capture
settings and exact software version.

If both reads match and validate, designate that exact hash as the current
calibration baseline. Compare it with the prior PPEI direct read and stock
reference. A difference from an old reference is not itself a failure: the tune
may have changed. Explain differences offline using the established XDF/mapping.
If A/B differ or fail validation, retain both, stop live exploration and inspect
logs/address echoes/power conditions; do not resolve the discrepancy by writing.

Passive output should state observed counts, direction/framing confidence and
any drop indication. Identity output should preserve the four-request outcomes.
Negative responses are evidence of those requests under those conditions only;
they do not establish a universal service contract.

## Stop conditions and what follows

Stop at an unexpected identity, failed anchor, unverified read, inconsistent
calibration, recurring transport errors, adapter overflow, falling/unstable
power, unexpected vehicle behavior or any attempted outbound packet outside the
allowlist. Cancel the current operation and preserve its log. Do not increase
timeouts or add services experimentally during the session. The existing reader's
already implemented bounded retry behavior remains unchanged.

No new addresses or services are added in response to an interesting frame.
Return to saved firmware analysis, establish what a proposed request actually
does, then prepare a separately reviewed bounded experiment if justified. Reads
of arbitrary mapped memory can have side effects, especially MMIO; “read-only”
is not sufficient justification for scanning the address space.

Successful completion yields a current calibration backup and better normal-mode
observations. Flash/FIFO identification, complete programming exchange, physical
erase geometry, current collateral/bank backups and demonstrated recovery remain
unresolved. The supplied encrypted EFX files remain available for independent
offline format analysis. No flash capture, tune change or destructive recovery
trial on the only TCM is part of this plan.
