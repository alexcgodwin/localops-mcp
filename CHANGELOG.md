# Changelog

## 0.3.0

- Added local TCP/UDP listener and active connection inventory for Windows and Linux.
- Added local routing-table, DNS configuration and validated DNS-resolution tools.
- Added read-only firewall status and bounded firewall-rule inspection.
- Added network adapter and ARP/neighbor-cache inventory.
- Added process-to-network mapping without packet capture or process command-line collection.
- Added caller-baseline comparison for unexpected listening ports and outbound TCP endpoints.
- Baseline deviations are explicitly not treated as malware or compromise determinations.
- Added Linux/Windows normalization and regression coverage for the network layer.
- v0.3 remains read-only and exposes no remote port scanning, packet capture, firewall mutation or arbitrary shell tool.

## 0.2.0

- Added installed software and version inventory for Windows and Linux package databases.
- Added caller-supplied software baseline comparison without local persistence.
- Added local user, group and administrator inventory.
- Added startup program and scheduled-task metadata while excluding command/action contents.
- Added certificate inventory and expiry checks without private-key reads.
- Added SSH key file metadata without reading key contents.
- Added environment-variable name inventory without exposing values.
- Expanded privacy and safety regression coverage.
- v0.2 remains read-only and exposes no mutation or arbitrary shell tool.

## 0.1.0

- Initial OpsChugex LocalOps MCP release.
- Read-only Windows and Linux system discovery.
- System, CPU, memory, disk, network, process and service inspection.
- No mutation, remediation or arbitrary shell tool is exposed.
