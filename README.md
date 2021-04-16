![Basic build](https://github.com/crypsisgroup/ebs-direct-sec-tools/workflows/Go/badge.svg)

# EBS Direct API Security Tooling

Fun tools around the EBS Direct API. If you find this interesting, give it a star, repost the blog, etc so I know whether I should do more! I've yet to ask that of other stuff I've open sourced or blogged about.

**All utilities have a build of latest for AMD64 Linux, Mac and Windows under Github Actions.**

### Authentication

Use native authentication. 

Use ~/.aws/credentials, environment variables, etc.

### Todo/Wishlist

- Flag enhancement - More options for end users
- Modularize signatures
- Multithreading: It's pretty slow. In my personal circumstances, still worth it, especially if you're doing it off a residential wifi+laptop and not your lab's datacenter, but slow.
- Figure out what exactly should go where (e.g. it doesn't make sense, say, scansecrets has a dumpbytes param and not diffsecrets, but then diffsecrets having a dump param would deprecate diffblocks - I wouldn't be surprised to see this collapse down into a unified tool)

Note: Some of these may be considered essential in some cases, however my priority is getting capabilities in the hands of users via "better out than perfect" principle.

## DownloadSnap 

This is a simple Go utility that can be used to download snapshots – This exists elsewhere but was written in Go for both performance and portability.

**NOTE: Two months ago during the course of this research AWS Labs came out with development code for “coldsnap” which does this. Downloadsnap also doesn't paginate.** The DownloadSnap code is still being made available as historical/example code. Good to see they also came out with it in a compilable language :smile: 

```
$ ./downloadsnap -h
Usage of ./downloadsnap:
  -id string
    	Snapshot ID of the desired image (default "empty")
  -region string
    	Snapshot ID of the desired image (default "us-east-1")
```

## DumpBlocks 

Go utility to dump snapshot fragments in a folder based on the changed blocks. For instance, if 40MB continuous changes, then there’s another 60MB later on the disk that changed, it creates 40MB and 60MB files. This is useful for contextualizing interesting fragments.

```
$ ./diffblocks  -h
Usage of ./diffblocks:
  -bar
    	Whether you want a progress bar thrust upon you
  -id string
    	Snapshot ID of the desired image (default "empty")
  -region string
    	Snapshot ID of the desired image (default "us-east-1")
  -second-id string
    	Snapshot ID of the desired image (default "empty")
```

## ScanSecrets 

Go utility augmenting Bishop Fox’s Dufflebag rules match function to scan a snapshot for potential hardcoded secrets. Amongst other things, this could be used to help enforce instance roles over hardcoded keys in a CI/CD environment.

```
$ ./scansecrets -h
Usage of ./scansecrets:
  -bar
    	Whether you want a progress bar thrust upon you
  -dumpbytes
    	Whether or not to dump the bytes in question to disk. 
  -id string
    	Snapshot ID of the desired image (default "empty")
  -region string
    	Snapshot ID of the desired image (default "us-east-1")
```

## DiffSecrets

Go utility augmenting Bishop Fox’s Dufflebag rules and match function to scan two different snapshots for potential hardcoded secrets. Amongst other things, this could be used to help enforce instance roles over hardcoded keys in a CI/CD environment.

The ScanSecrets tool, but diffs two snapshots. This is a pretty niche but really valuable API (and, in my opinion, fun to play with). In testing this was able to sniff out hardcoded keys and backdoor /etc/shadow passwords left over after basic iterative AMI changes in seconds. On a home laptop on home WiFi.

```
$ ./diffsecrets -h
Usage of ./diffsecrets:
  -bar
    	Whether you want a progress bar thrust upon you
  -id string
    	Snapshot ID of the desired image (default "empty")
  -region string
    	Snapshot ID of the desired image (default "us-east-1")
  -second-id string
    	Snapshot ID of the desired image (default "empty")
```
DiffSecrets Demo: 

[![asciicast](https://asciinema.org/a/urSwi8QSTNGV9IGn2efLhTKOi.svg)](https://asciinema.org/a/urSwi8QSTNGV9IGn2efLhTKOi)
