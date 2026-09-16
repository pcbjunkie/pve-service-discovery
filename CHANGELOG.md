# Changelog

## 0.3.0 - 2026-09-16

Initial public release.

- Discovers HTTP and HTTPS services in running local LXCs.
- Publishes clickable links in a safely managed Proxmox Notes block.
- Preserves manual Notes content and uses Proxmox configuration digests to
  reject concurrent edits.
- Handles nested application paths such as Apache Guacamole's `/guacamole/`.
- Lists distinct working root and nested application URLs.
- Supports per-container address, port, label, path, and scheme overrides.
- Includes dry-run, verbose, single-container, and managed-note removal modes.
- Installs as a lightweight systemd timer with no container-side agent.
