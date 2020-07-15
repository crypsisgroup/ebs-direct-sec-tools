package main

// The name of the tool is a slight misnomer as there's a chance it grabs an incremental image if the snapshot is
// truly incremental, but in practice it seldom is

import ( "fmt"
"io"
"github.com/superhawk610/bar"
"github.com/aws/aws-sdk-go/aws"
"github.com/aws/aws-sdk-go/aws/session"
"github.com/aws/aws-sdk-go/service/ebs"
"os"
"flag"
"github.com/aws/aws-sdk-go/service/ec2"
)

func write_buffer_to_file(buffer io.ReadCloser,filename string) {
        // write the whole body at once
        // append flags so it doesn't write 512K chunks over one another
        outFile, err :=  os.OpenFile(filename, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0660);
        // handle err
        defer outFile.Close()
        _, err = io.Copy(outFile, buffer)
        if err != nil {
            fmt.Println(err)
        }
}

func process_snapshot(snapid string, region string) {
    //I would love to be able to multithread this
    sess := session.Must(session.NewSession(&aws.Config{
        MaxRetries: aws.Int(3),
    }))

    // Create S3 service client with a specific Region.
    ebssvc := ebs.New(sess, &aws.Config{
        Region: aws.String(region),
    })
    // Basically a debug print statement but it's fine
    fmt.Println("Processing "+snapid)
    params := &ebs.ListSnapshotBlocksInput{SnapshotId: aws.String(snapid)}
    // Get a list of bytes blocks available in the snapshot
    req, resp := ebssvc.ListSnapshotBlocksRequest(params)
    
    err := req.Send()
    if err == nil { // resp is now filled
        fmt.Println("Removing prior image if any")
        // Remove prior image because we append when we write
        os.Remove("output-"+snapid)
        fmt.Println("Retrieving block data")
        b := bar.New(len(resp.Blocks))
        for _ ,blockref := range resp.Blocks {
            blockparams := &ebs.GetSnapshotBlockInput{BlockIndex: blockref.BlockIndex, BlockToken: blockref.BlockToken, SnapshotId: aws.String(snapid)}
            // Get a byte blocks available in the snapshot
            block, _ := ebssvc.GetSnapshotBlock(blockparams)

            // filename should be configurable in the future
            // get the actual bytes from the blocks
            write_buffer_to_file(block.BlockData,"output-"+snapid)
            b.Tick()
        }
        b.Done()
        fmt.Println("Finished image")
    }
}

func main() {
    // Optional: -region, required: -id
    // No help page because I just haven't yet
    snapid := flag.String("id", "empty", "Snapshot ID of the desired image")
    region := flag.String("region", "us-east-1", "Snapshot ID of the desired image")
    flag.Parse()
    // Create Session with MaxRetries configuration to be shared by multiple
    // service clients.
    // maybe this should be a param/default?
    sess := session.Must(session.NewSession(&aws.Config{
        MaxRetries: aws.Int(3),
    }))

    // Create S3 service client with a specific region -- 99% of it is
    svc := ec2.New(sess, &aws.Config{
        Region: aws.String(*region),
    })

	describeSnapshotsInput := &ec2.DescribeSnapshotsInput{OwnerIds: []*string{
        aws.String("self"),
    },}
    req, resp := svc.DescribeSnapshotsRequest(describeSnapshotsInput)

    err := req.Send()
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
    snaplist := make([]*ec2.Snapshot, 0)
    snaplist = append(snaplist, resp.Snapshots...)
    // Paginate snapshot calls
    for resp.NextToken != nil {
        describeSnapshotsInput := &ec2.DescribeSnapshotsInput{OwnerIds: []*string{
            aws.String("self"),
        },
        NextToken: resp.NextToken}
        req, resp := svc.DescribeSnapshotsRequest(describeSnapshotsInput)

        err := req.Send()
    
		if err != nil {
            fmt.Println(err)
            os.Exit(1)
        }
        fmt.Println("New round")
		snaplist = append(snaplist, resp.Snapshots...)
    }
    // Show us our Snap choice
    fmt.Println("Selected:")
    fmt.Println(*snapid)
    snapFound := false
    if err == nil { // resp is now filled
        for _, s := range snaplist {
            if *snapid == *s.SnapshotId {
                snapFound = true
            }
        }
    } else {
        fmt.Println(err)
        os.Exit(1)
    }
    // I get this isn't performant and I should seek the snap directly, 
    // but this is so I can build it out towards pentesting and it's a small one
    // time performance cost
    if snapFound {
        process_snapshot(*snapid, *region)
    } else {
        fmt.Println("Couldn't locate the selected snapshot")
    }
}