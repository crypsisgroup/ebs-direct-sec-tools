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
"strings"
"regexp"
)

// Inspector Function from Dufflebag
// https://github.com/BishopFox/dufflebag/blob/master/inspector.go
// CREDIT: BISHOP FOX
// Reasonably modified from their signatures
func checkContentsRegex(b []byte) []string {
	//regex defs
    re_shadow_entry := regexp.MustCompile(`[a-z\_\-\.\@]{1,60}:\$[a-z0-9-]+\$[0-9A-Za-z.\/+=,$-]+:`)
    // too many false positives in OS fragments
    // disabled
    //re_ssh_private := regexp.MustCompile(`-----(BEGIN|END)[\s](DSA|RSA|EC|OPENSSH)[\s]PRIVATE[\s]KEY-----`)
	re_aws_mws := regexp.MustCompile(`amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	re_aws_access_key := regexp.MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`)
	re_aws_secret_key := regexp.MustCompile(`("|')?(AWS|aws|Aws)+_?(SECRET|secret|Secret)+_?(ACCESS|access|Access)?_?(KEY|key|Key)("|')?\s*(:|=>|=)\s*("|')?[A-Za-z0-9\/\+=]{40}("|')?`)
    re_aws_account_key := regexp.MustCompile(`("|')?(AWS|aws|Aws)+_?(ACCOUNT|account|Account)_?(ID|id|Id)?("|')?\s*(:|=>|=)\s*("|')?[0-9]{4}\-?[0-9]{4}\-?[0-9]{4}("|')?`)
    re_slack_api_key := regexp.MustCompile(`(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})`)
    re_slack_webhook := regexp.MustCompile(`https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`)
    // less success since we lose context - Dufflebag gets by this seemingly by actually respecting the filesystem, we're working in a block context
	//re_generic_secret := regexp.MustCompile(`(-----(BEGIN|END)[\s]PRIVATE[\s]KEY-----)|([s|S][e|E][c|C][r|R][e|E][t|T].*('|")[0-9a-zA-Z]{32,45}('|"))|([a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*('|")[0-9a-zA-Z]{32,45}('|"))|([a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}("|'|\s))|(('|")[0-9a-zA-Z]{32,64}('|"))|([0-9a-z]{32,64})`)
    
    //api-key is a bit generic so hard to hit on
    // disabled
    //re_api_key := regexp.MustCompile(`(?i)[a-z]+[_-]?api[_-]?key[\s]*=[\s]*["'a-z0-9]`)

	var regex_results = make([]string, 0)
    // disabled from bishop fox, too many hits on a base image
    // if you're looking for plants, you probably care more about pubkeys anyways :)
	//TODO - lots of duplication here, some kind of iterator needed!
	//if re_ssh_private.Find(b) != nil {
		// this file has a hit!, make sure we record this!
	//	regex_results = append(regex_results, "re_ssh_private")
	//}
	if re_aws_mws.Find(b) != nil {
		// this file has a hit!, make sure we record this!
		regex_results = append(regex_results, "re_aws_mws")
    }
    if re_shadow_entry.Find(b) != nil {
        // pillage the neckbeards!
        fmt.Println("Finding: Shadow Entry [Medium-High Fidelity Signature]")
        fmt.Println("Finding Data:\n")
        fmt.Printf(string(re_shadow_entry.Find(b)))
        fmt.Println("\n---------------\n")
		regex_results = append(regex_results, "re_shadow_entry")
    }
	if re_aws_access_key.Find(b) != nil {
        // this file has a hit!, make sure we record this!
        // write it to screen because I like pain
        fmt.Println("Finding: AWS Access Key [Medium-High Fidelity Signature]")
        fmt.Println("Finding Data:\n")
        fmt.Printf(string(re_aws_access_key.Find(b)))
        fmt.Println("\n---------------\n")
		regex_results = append(regex_results, "re_aws_access_key")
	}
	if re_aws_secret_key.Find(b) != nil {
		// this file has a hit!, make sure we record this!
        // write it to screen because I like pain
        fmt.Println("Finding: AWS Secret [Medium-High Fidelity Signature]")
        fmt.Println("Finding Data:\n")
        fmt.Printf(string(re_aws_secret_key.Find(b)))
        fmt.Println("\n---------------\n")
        regex_results = append(regex_results, "re_aws_secret_key")
	}
	if re_aws_account_key.Find(b) != nil {
		// this file has a hit!, make sure we record this!
        // write it to screen because I like pain
        fmt.Println("Finding: AWS Account Key [Medium-High Fidelity Signature]")
        fmt.Println("Finding Data:\n")
        fmt.Printf(string(re_aws_account_key.Find(b)))
        fmt.Println("\n---------------\n")
		regex_results = append(regex_results, "re_aws_account_key")
    }
    // Disabled from bishop fox, tons of hits
	//if re_generic_secret.Find(b) != nil {
		// this file has a hit!, make sure we record this!
	//	regex_results = append(regex_results, "re_generic_secret")
    //}
	if re_slack_api_key.Find(b) != nil {
		// this file has a hit!, make sure we record this!
        fmt.Println("Finding: Slack API Key [Medium Fidelity Signature]")
        fmt.Println("Finding Data:\n")
        fmt.Printf(string(re_slack_api_key.Find(b)))
        fmt.Println("\n---------------\n")
        regex_results = append(regex_results, "re_slack_api_key")
    }
	if re_slack_webhook.Find(b) != nil {
		// this file has a hit!, make sure we record this!
        fmt.Println("Finding: Slack Webhook [Medium Fidelity Signature]")
        fmt.Println("Finding Data:\n")
        fmt.Printf(string(re_slack_webhook.Find(b)))
        fmt.Println("\n---------------\n")
        regex_results = append(regex_results, "re_slack_webhook")
	}
    /*
    
    Including these from the Bishop Fox! Chop them up, move them around, etc as you desire 


	(-----(BEGIN|END)[\s]PRIVATE[\s]KEY-----)|([s|S][e|E][c|C][r|R][e|E][t|T].*('|")[0-9a-zA-Z]{32,45}('|"))|([a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*('|")[0-9a-zA-Z]{32,45}('|"))|([a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}("|'|\s))|(('|")[0-9a-zA-Z]{32,64}('|"))|([0-9a-z]{32,64})
	    # Keep this file alphabetically sorted by Providers
	#
	# Resources:
	#    https://github.com/dxa4481/truffleHogRegexes/blob/master/truffleHogRegexes/regexes.json
	#    https://blog.acolyer.org/2019/04/08/how-bad-can-it-git-characterizing-secret-leakage-in-public-github-repositories/
	# Amazon
	    amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}
	    AKIA[0-9A-Z]{16}
	# DSA/RSA/EC/OPENSSH Private key
	    -----(BEGIN|END)[\s](DSA|RSA|EC|OPENSSH)[\s]PRIVATE[\s]KEY-----
	# Facebook
	    EAACEdEose0cBA[0-9A-Za-z]+
	    [f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*('|")[0-9a-f]{32}('|")
	# Generic
	    -----(BEGIN|END)[\s]PRIVATE[\s]KEY-----
	    [s|S][e|E][c|C][r|R][e|E][t|T].*('|")[0-9a-zA-Z]{32,45}('|")
	    [a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*('|")[0-9a-zA-Z]{32,45}('|")
	    [a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}("|'|\s)
	    ('|")[0-9a-zA-Z]{32,64}('|")
	    [0-9a-z]{32,64}
	# Google
	    AIza[0-9A-Za-z\-_]{35}
	    [0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com
	    4/[0-9A-Za-z\-_]+
	    1/[0-9A-Za-z\-_]{43}
	    1/[0-9A-Za-z\-_]{64}
	    ya29\.[0-9A-Za-z\-_]+
	    AIza[0-9A-Za-z\-_]{35}
	    ('|")client_secret('|"):('|")[a-zA-Z0-9_]{24}('|")
	    ('|")type('|"):[\s]('|")service_account('|")
	# Github
	    [g|G][i|I][t|T][h|H][u|U][b|B].*('|")[0-9a-zA-Z]{35,40}('|")
	# Heroku
	    [h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}
	# MailChimp
	    [0-9a-f]{32}-us[0-9]{1,2}
	# Mailgun
	    key-[0-9a-zA-Z]{32}
	# Modular Crypt Format
	    \$[a-z0-9-]+\$[0-9A-Za-z./+=,$-]+
	# PGP Private key
	    -----(BEGIN|END)[\s]PGP[\s]PRIVATE[\s]KEY[\s]BLOCK-----
	# PayPal
	    access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}
	# Picatic
	    sk_live_[0-9a-z]{32}
	# Slack
	    (xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})
	    https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}
	# Square
	    sq0atp-[0-9A-Za-z\-_]{22}
	    sq0csp-[0-9A-Za-z\-_]{43}
	# Stripe
	    sk_live_[0-9a-zA-Z]{24}
	    rk_live_[0-9a-zA-Z]{24}
	# Twilio
	    SK[0-9a-fA-F]{32}
	# Twitter
	    [1-9][0-9]+-[0-9a-zA-Z]{40}
	    [t|T][w|W][i|I][t|T][t|T][e|E][r|R].*('|")[0-9a-zA-Z]{35,44}('|")
	# vim:ft=text
	*/

	return regex_results
}

func write_and_scan_buffer(buffer io.ReadCloser,filename string, bufferwrite bool) {
        // write the whole body at once
        // append flags so it doesn't write 512K chunks over one another
        body, err := ioutil.ReadAll(buffer)
        outputs := checkContentsRegex(body)
        if len(outputs) > 0 {
            fmt.Printf("\nMatch type: %v\n----------\n", outputs)
        }
        if bufferwrite == true { 
            outFile, _ :=  os.OpenFile(filename, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0660);
            // handle err
            defer outFile.Close()        
            _, wterr := outFile.Write(body)
            if wterr != nil {
            fmt.Println(err)
            }
        }
}

func process_snapshot(snapid string, wantsbar bool, region string, next_token string, bufferwrite bool) {
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
    params := &ebs.ListSnapshotBlocksInput{SnapshotId: aws.String(snapid)}
    // Example sending a request using the ListSnapshotBlocksRequest method.
    fmt.Println("Removing prior image if any")
    os.Remove("output-"+snapid)
    pages := 0
    err := ebssvc.ListSnapshotBlocksPages(params,
        func(page *ebs.ListSnapshotBlocksOutput, lastPage bool) bool {
            pages++
            return true
        })
    fmt.Println("Pages available: "+strconv.Itoa(pages))
    activePage := 0 
    listerr := ebssvc.ListSnapshotBlocksPages(params, 
    func(page *ebs.ListSnapshotBlocksOutput, lastPage bool) bool {
        activePage++
        fmt.Println("Page: "+strconv.Itoa(activePage))
        // Remove prior image because we append when we write
        fmt.Println("Retrieving block data")
        b := bar.New(len(page.Blocks))
        for _ ,blockref := range page.Blocks {
            blockparams := &ebs.GetSnapshotBlockInput{BlockIndex: blockref.BlockIndex, BlockToken: blockref.BlockToken, SnapshotId: aws.String(snapid)}
            block, getbyteserr := ebssvc.GetSnapshotBlock(blockparams)
            if getbyteserr != nil {
                fmt.Println("Error getting snapshot block bytes: "+getbyteserr.Error())
            }
            // filename should be configurable
            write_and_scan_buffer(block.BlockData,"output-"+snapid, bufferwrite)
            if wantsbar == true {
                b.Tick()
            }
        }
        if wantsbar == true {
            b.Done()
        }
        return true
    })
    if err == nil { // resp is now filled

        fmt.Println("\n\nFinished snapshot differential")
    } else {
        fmt.Println("Error handling snapshot block listing: "+err.Error())
    }
    if listerr != nil { // resp is now filled
        fmt.Println("Error handling snapshot block listing: "+err.Error())
    }
}

func main() {
    // Optional: -region, required: -id
    // No help page because I just haven't yet
    snapid := flag.String("id", "empty", "Snapshot ID of the desired image")
    // Had to remove this for pagination, TODO: add it back
    bar := flag.Bool("bar", false, "Whether you want a progress bar thrust upon you")
    region := flag.String("region", "us-east-1", "Snapshot ID of the desired image")
    bufferwrite := flag.Bool("dumpbytes",false,"Whether or not to dump the bytes in question to disk.")
    flag.Parse()
    if (!strings.HasPrefix(*snapid, "snap-")) {
        fmt.Printf("Invalid snapshot or no snapshot provided (-id). It should start with snap-.....\n")
        os.Exit(1)
    }
    region_regex := regexp.MustCompile(`[a-z]{1,15}-[a-z]{1,15}-[0-9]{1,3}`)
    if region_regex.Find([]byte(*region)) == nil {
        fmt.Printf("Invalid region provided (-region). Basic region format doesn't match.\n")
        os.Exit(1)
    }
    // Create Session with MaxRetries configuration to be shared by multiple
    // service clients.
    // maybe this should be a param/default?
    //sess := session.Must(session.NewSession(&aws.Config{
    //    MaxRetries: aws.Int(3),
    //}))
    // I get this isn't performant and I should seek the snap directly, 
    // but this is so I can build it out towards pentesting and it's a small one
    // time performance cost
    process_snapshot(*snapid, *bar, *region, "none", *bufferwrite)
}