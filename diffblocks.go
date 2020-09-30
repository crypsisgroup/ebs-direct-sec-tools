package main

import ( "fmt"
"io"
"github.com/superhawk610/bar"
"github.com/aws/aws-sdk-go/aws"
"github.com/aws/aws-sdk-go/aws/session"
"github.com/aws/aws-sdk-go/service/ebs"
"os"
"flag"
"strconv"
"io/ioutil"
)

func write_and_scan_buffer(buffer io.ReadCloser,filename string) {
        // write the whole body at once
        // append flags so it doesn't write 512K chunks over one another
        body, _ := ioutil.ReadAll(buffer)
        outFile, err :=  os.OpenFile(filename, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0660);
        // handle err
        defer outFile.Close()        
        _, wterr := outFile.Write(body)
        if wterr != nil {
           fmt.Println(err)
        }
}

func process_snapshot(snapid string, secondsnapid string, wantsbar bool, region string) {
    //I would love to be able to multithread this
    sess := session.Must(session.NewSession(&aws.Config{
        MaxRetries: aws.Int(3),
    }))

    // Create EBS service client with a specific Region.
    ebssvc := ebs.New(sess, &aws.Config{
        Region: aws.String(region),
    })
    // Basically a debug print statement but it's fine
    fmt.Println("Processing "+snapid)
    params := &ebs.ListChangedBlocksInput{FirstSnapshotId: aws.String(snapid), SecondSnapshotId: aws.String(secondsnapid)}
    // Example sending a request using the ListChangedBlocksRequest method.
    req, resp := ebssvc.ListChangedBlocksRequest(params)
    err := req.Send()
    if err == nil { // resp is now filled
        fmt.Println("Removing prior image if any")
        // Remove prior image because we append when we write
        fmt.Println("Retrieving block data")
        b := bar.New(len(resp.ChangedBlocks))
        blockid := 0
        segment := 0
        if _, err := os.Stat("diffs"); os.IsNotExist(err) {
            os.Mkdir("diffs", 0700)
        }
        for _ ,blockref := range resp.ChangedBlocks {
            blockparams := &ebs.GetSnapshotBlockInput{BlockIndex: blockref.BlockIndex, BlockToken: blockref.SecondBlockToken, SnapshotId: aws.String(secondsnapid)}
            block, _ := ebssvc.GetSnapshotBlock(blockparams)
            // filename should be configurable
            activeblockloc := int(*blockref.BlockIndex)
            if blockid != activeblockloc {
                segment = segment + 1
                blockid = activeblockloc
            }
            write_and_scan_buffer(block.BlockData,"diffs/diff-"+snapid+"-"+strconv.Itoa(segment))
            if wantsbar == true {
                b.Tick()
            }

        }
        if wantsbar == true {
            b.Done()
        }
        fmt.Println("\n\nFinished snapshot differential")
    }
}

func main() {
    // Optional: -region, required: -id
    // No help page because I just haven't yet
    snapid := flag.String("id", "empty", "Snapshot ID of the desired image")
    bar := flag.Bool("bar", false, "Whether you want a progress bar thrust upon you")
    secondsnapid := flag.String("second-id", "empty", "Snapshot ID of the desired image")
    region := flag.String("region", "us-east-1", "Snapshot ID of the desired image")
    flag.Parse()
    // Create Session with MaxRetries configuration to be shared by multiple
    // service clients.
    // maybe this should be a param/default?
    //sess := session.Must(session.NewSession(&aws.Config{
    //    MaxRetries: aws.Int(3),
    //}))
    // I get this isn't performant and I should seek the snap directly, 
    // but this is so I can build it out towards pentesting and it's a small one
    // time performance cost
    process_snapshot(*snapid, *secondsnapid, *bar, *region)
}