# Reading the remaining modeled AL5 flash regions

## New source binding and permission observations

The exact downloaded SPS OS 15184109 (679,828 bytes; SHA256 145d0dde8c4de88e3145b5693685ab28958d1dda70743c589cc0c7deaa4b45e7) contains byte-identical Mode 23 handler/helper windows to the previously pinned HIGH image: 0xBFDA0-0xBFE47, 0xC00E8-0xC018D, 0xC2F88-0xC2FCD and 0xC2FD0-0xC2FF5. The new audit pins the entire SPS module and all four code digests. This binds earlier permission findings to the downloaded OS code; it does not independently read back installed OS bytes.

The existing isolated Probe now accepts an explicit sps_os source profile, pins this exact module, and maps the unavailable upper tail as synthetic inert memory. The default legacy HIGH identity check is unchanged. Twenty-three native boundary/overlap samples agree with the derived permission model, including boot/persistent, calibration, lower-tail, OS and upper-tail endpoints. Execution stays in the old allowlisted read-only handler/helper harness with synthetic RAM and no transport or peripheral execution.

## Coverage and hard holes

The modeled flash address space is 0x000000-0x0FFFFF. Mode 23 permissions exclude four bytes at 0x3FD8-0x3FDB and two bytes at 0xC4C66-0xC4C67. This leaves six bytes that this stock handler cannot return. A strictly aligned dword scan misses eight bytes because the second exclusion shares a dword with two allowed bytes. Native permission accepts an overlapping dword at 0xC4C62, which could supply 0xC4C64/65, but neither that unaligned read nor broader live ranges are physically qualified.

The 41,000-byte lower tail 0x15FD8-0x1FFFF and 237,676-byte upper tail 0xC5F94-0xFFFFF contain none of these permission exclusions. The persistent-region address interval 0x4000-0x7FFF also has no such exclusion. This is permission coverage only, not evidence of a successful acquisition or physical erase preservation. The excluded boot/OS bytes cannot be replaced with bytes from the downloaded SPS OS and then labeled independent readback.

## Offline tool extensions

- audit_sps_read_regions.py validates the SPS code identity, reports region sizes, exclusions and aligned-read gaps, and optionally executes native samples. It emits no vehicle requests.
- AL5SpsSavedFlashCoverage owns a separate known-byte mask for caller-supplied saved dwords. It pins the SPS OS, checks full-dword permission, rejects conflicting overlaps atomically and returns range data only when every byte is present. Internal zero initialization never counts as observed evidence. It exposes no full image when holes remain.
- The new BCL-only SpsSavedFlashCoverageTest fills permitted intervals with synthetic observations and demonstrates exactly six retained unknown bytes after the allowed overlap. It tests bounds, forbidden crossings, immutable output, conflicting overlap atomicity and blocked live/freshness/full-address flags. Those synthetic bytes are not vehicle data.

The existing Mode 23 parser/session remains deliberately restricted to its previous address profile. No request builder, live reader range, retry policy, memory upload or write gate is changed.

## What still prevents a verified full read

A positive Mode 23 reply echoes only the low two address bytes. Earlier native tracing also established a shared response body, pending-bit clearing before transmission and a scheduler that is not a FIFO. Neither software queue emptiness, adapter flush, arbitrary delay nor a later unrelated query proves earlier responses invalidated. Starting a new offline correlation instance is not a physical session boundary.

The most useful next trace is the peripheral submission/completion and receive-invalidation path in the pinned SPS OS, including interrupt callers of 0x70AA8/0x70CE0. A broader live reader needs a justified single-pending correlation and timeout/stop policy before bank transitions. Six excluded bytes require a separate independently qualified acquisition path if complete flash verification is required. The captured SPS programming loader is not qualified for read-only use.

No newly acquired flash bytes are claimed by this audit. The independently verified 57,304-byte calibration remains the only current PcmHammer readback from this SPS session. OS, tails and protected-prefix physical preservation remain unverified; live writes and broader live reads stay disabled.
