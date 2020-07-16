# EBS Direct API Tooling

EBS Direct APIs are designed to allow you to upload, download and diff EBS *snapshots*. EBS snapshots are designed to be incremental, but:
- AMIs are compromised of EBS snapshots
- EBS snapshots commonly become non-incremental where you'd think they would be incremental, e.g. cross-account
- 

These APIs are being studied for forensic implications, offensive implications, and defensive implications. Use cases include:
- Scanning incremental releases of images for secrets for CI/CD
- Scanning incremental or mass releases for secrets for offensive purposes
- Differentiating two backups during a compromise period to determine changed bytes

Crypsis PR work around this is pending.
