# Source provenance

New lemonades integration is distributed under BSD-2-Clause-Patent (see LICENSE).
Existing source-file notices and upstream licenses continue to apply.

- Generic drivers, ABI declarations and build recipes derive from UniXNU at
  `7b52e7968c76453cdc18b5aa174fc368d5293b91`.
- Diagnostic display and related device integration derive from UniXNU-sheng at
  `a599a1a8a92093b5077543e071b72130769eb325`. Detailed file pins remain in
  `package/boot-progress/upstream.json` and `package/legacy-display/upstream.json`.
- Firmware overlays derive from uefi-sheng at
  `329b473df1e53a3bfa64b2b39b79670c4c02279b` and retain their file notices.
- The ST FTS protocol and board wiring derive from the umi port's checks against
  MiCode's public `umi-q-oss` kernel. For lemonades the corresponding references
  are the LineageOS SM8250 kernel and the OPLUS kona kernel sources; the
  Synaptics S3908 touch path needs its own review against those before any
  driver work. The original Linux drivers are not bundled; references do not
  relicense their source. Additional references are in `SOURCES.txt` files.

Apple restore components and vendor firmware are external inputs, not licensed
or distributed by this repository. Local filesystem evidence references in
source notes describe private research records, not downloadable artifacts.
