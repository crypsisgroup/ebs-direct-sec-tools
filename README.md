# EBS Direct API Security Tooling

Fun tools around the EBS Direct API. If you find this interesting, give it a star, repost the blog, etc so I know whether I should do more! I've yet to ask that of other stuff I've open sourced or blogged about.

Please be gentle about my code. My time is limited and my worst Go code is faster than my best Ruby code so I just went for it.

**All utilities have a release of latest for AMD64 Linux, Mac and Windows**

## DownloadSnap 

This is a simple Go utility that can be used to download snapshots – This exists elsewhere but was written in Go for both performance and portability.

**NOTE: Two months ago during the course of this research AWS Labs came out with development code for “coldsnap” which does this.** The DownloadSnap code is still being made available as historical/example code. Good to see they also came out with it in a compilable language :smile:

## DumpBlocks 

Go utility to dump snapshot fragments in a folder based on the changed blocks. For instance, if 40MB continuous changes, then there’s another 60MB later on the disk that changed, it creates 40MB and 60MB files. This is useful for contextualizing interesting fragments.

```

```

## ScanSecrets 

Go utility augmenting Bishop Fox’s Dufflebag rules match function to scan a snapshot for potential hardcoded secrets. Amongst other things, this could be used to help enforce instance roles over hardcoded keys in a CI/CD environment.

```

```

## DiffSecrets

Go utility augmenting Bishop Fox’s Dufflebag rules and match function to scan two different snapshots for potential hardcoded secrets. Amongst other things, this could be used to help enforce instance roles over hardcoded keys in a CI/CD environment.

The ScanSecrets tool, but diffs two snapshots. This is a pretty niche but really valuable API (and, in my opinion, fun to play with). In testing this was able to sniff out hardcoded keys and backdoor /etc/shadow passwords left over after basic iterative AMI changes in seconds. On a home laptop on home WiFi.

```

```