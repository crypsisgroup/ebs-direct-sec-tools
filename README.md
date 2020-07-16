# EBS Direct API Tooling

EBS Direct APIs are designed to allow you to upload, download and diff EBS *snapshots*. AWS seems to brand them for [other IaaS/SaaS providers](https://aws.amazon.com/about-aws/whats-new/2019/12/aws-launches-ebs-direct-apis-that-provide-read-access-to-ebs-snapshot-data-enabling-backup-providers-to-achieve-faster-backups-of-ebs-volumes-at-lower-costs/) despite how affordable they are, so they seem to have been largely overlooked. EBS snapshots are designed to be incremental, but:
- AMIs are compromised of EBS snapshots
- EBS snapshots commonly become non-incremental where you'd think they would be incremental, e.g. cross-account

These APIs are being studied for forensic implications, offensive implications, and defensive implications. Use cases include:
- Scanning incremental releases of images for secrets for CI/CD
- Scanning incremental or mass releases for secrets for offensive purposes
- Differentiating two backups during a compromise period to determine changed bytes

Crypsis PR work around this is pending.

# Individual Tools

## capturefullimage.go

A bit of a misnomer, this tool won't capture a full image but rather a snapshot. Run with ./capturefullimage -id snapshotidhere -region regionhere, e.g. ./capturefullimage -id snap-aab1lan2a -region us-east-1 and it will output to output-snap-aab1lan2a to the current directory. This was meant to be a proof of concept to set expectations around the API and work on the API.
