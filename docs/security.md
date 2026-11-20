# Security and privacy

## Trust boundaries

APK content is untrusted. The API limits streaming bodies and validates the archive marker. The separate scanner checks ZIP headers, duplicate names, offsets, paths, entry counts, compression methods, uncompressed sizes, and CRC while reading. It leaves entries in the archive. Static APK parsing uses a timed child process and Android signature verification uses a bounded Java process. The worker drops Linux capabilities, runs without root, and uses read-only container filesystems with limited writable mounts. The scanner runs with `network_mode: none`, receives only the current intake through a read-only volume, and uses a separate evidence exchange. The production platform should dedicate an isolated machine or VM to this stack when accepting uploads from untrusted parties. The Windows Python fallback uses a local user and process boundary.

User sessions carry ownership checks on all scan, comparison, and report routes. Passwords use Argon2id and session tokens are stored as hashes. Admin accounts are created by an operator. A recovery operation revokes existing sessions. Browser mutation endpoints require a custom same-origin request header and use Strict same-site cookies. Configure secure cookies for HTTPS. Report text is escaped in HTML and PDF rendering. The app lists embedded hosts without making DNS or HTTP requests to them.

## Storage and retention

APK files are transient. Uploads are removed after terminal state or picked up by periodic cleanup, including queued cancellations and interrupted uploads. The parser exchange may hold a copy of extracted JSON evidence for up to five minutes while healthy. Reports expire after 30 days by default and can be deleted by their owner. Reports may contain package identifiers, signing subjects, resource names, manifest fields, and embedded hosts. PostgreSQL backups retain prior report data under the operator’s backup and deletion policy. Keep volumes and backup storage restricted and encrypted as appropriate.

## Coverage

Signing verification depends on the installed apksigner version and the APK’s schemes. The catalog compares whole approved signer sets, including separately reviewed historical sets for rotation or different distribution arrangements. Catalog entries are operator assertions backed by recorded provenance. The scanner records a signature mismatch as an authenticity finding. Icon similarity uses raster fingerprints and label similarity uses Unicode-normalized strings.

DEX method IDs can originate from inactive code or dependencies. The scanner reports selected references, native library inventory, manifest settings, and a limited hostname inventory. It performs no runtime execution, native decompilation, certificate lineage policy enforcement, or general packer identification. More complex adaptive resource resolution, split APK sets, and unusual container layouts can reduce coverage. No samples are sent to scanning providers. Dynamic analysis is outside the shipped deployment.

If configured, the threat indicator snapshot contains `version` and an `entries` array. Each entry has `type` (`apk_sha256` or `embedded_host`), `value`, HTTPS `source`, and `context`. Review and hash the snapshot before configuring it. A hostname match is a lead. A file hash match associates the exact file with an operator-reviewed threat record.

## Operational review

Review dependency and base image advisories before exposing any deployment. Observe failed and queued jobs, storage use, worker health, and log volume. Disable open signup for controlled deployments. Restrict diagnostics and database access. The shipped baseline intentionally uses a single dispatch worker. A hostile workload, vulnerable native parser, Docker kernel defect, or compromised operator account can still affect availability or evidence integrity.
