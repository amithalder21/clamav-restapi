# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v2.1.0] - 2026-09-03

### Added
- **Multi-Engine Scanning**: Integrated YARA (behavioral analysis) and Linux Malware Detect (Maldet) directly into the ClamTrac backend. The engines run concurrently across multiple goroutines, minimizing scan latency while significantly maximizing detection rates for zero-day threats, web-shells, and ransomware.
- **SaaS Multi-Tenancy**: Added robust multi-tenant architecture designed for the Polestar product suite (e.g. PurpleTrac, DocIntel). It implements JWT RS256 validation via Cognito, data isolation via Dragonfly DB cache partitioning, and S3 Quarantine Folder isolation (routing malicious files to `s3://clamrest-quarantine/<tenant_id>/...`).
- **Dynamic Threat Intel Daemon**: Introduced an autonomous background updater (`update_signatures.sh`). The script clones your specified YARA `signature-base` repository every 12 hours, dynamically rebuilds the YARA index (`index.yar`), and updates Maldet signatures—all without requiring a Docker container rebuild.
- **Unified CLI Tool**: Added the `./clamtrac` command-line utility to orchestrate operations. All scattered Bash scripts have been consolidated under a `.tests/` directory. You can now use `./clamtrac test e2e`, `./clamtrac test api`, and `./clamtrac docker restart` to cleanly manage the repository.

### Changed
- **Memory Footprint & ECS Optimization**: The Docker container has been heavily optimized and can now successfully run inside a **2GB minimum ECS Task**. 
  - Purged 9 redundant, heavy Sanesecurity community databases from the `Dockerfile` to free up hundreds of megabytes of RAM.
  - Disabled `ConcurrentDatabaseReload` in `clamd.conf` via the entrypoint. This eliminates the 4GB OOM (Out-of-Memory) spikes that would occur during background signature refreshes.
- **Go Upgrade & Security Hardening**: Migrated the core application to `go 1.26.8` and the Docker base to `golang:1.26-alpine`. This patches 27 standard library vulnerabilities (including CVE-2026-4601 and CVE-2026-4340).
- **Rocky Linux Migration**: Swapped the runtime Alpine container layer to `rockylinux:9` to ensure enterprise compliance and properly support Maldet's GNU dependencies.

### Removed
- Removed static mock EICAR YARA rules (`/yara_rules`) in favor of the dynamic GitHub-backed threat intel daemon.
- Removed the old `test-multi-tenant.sh`, `test-endpoints.sh`, and `test-aws.sh` from the repository root (migrated to the `./clamtrac` CLI).
