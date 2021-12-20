package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/alecthomas/kong"
	"github.com/joshdk/go-junit"
	"github.com/schollz/progressbar/v3"
	"google.golang.org/api/iterator"
)

type status string

const (
	statusPassed status = "passed"
	statusFailed status = "failed"
)

// Watch out, one test case outcome may appear twice in the array of testcases.
// We do not do de-duplication yet.
type ginkgoResult struct {
	// The Name of the ginkgo result is of the form:
	//  [Conformance] Certificates with issuer type External ClusterIssuer should issue a cert with wildcard DNS Name
	// Note that the string '[It]' does not appear in the test Name.
	Name string `json:"name"`

	// The Status of the gingko test result. Can be "failed", "error", or
	// "passed". The "skipped" statuses are not dealt with in prowdig.
	Status status `json:"status"`

	// The Duration of the test case.
	Duration time.Duration `json:"duration"`

	// (optional) The error message shown right before the keyword 'occurred' at
	// the bottom of the ginkgo block.
	Err string `json:"err"`

	// (optional) The Go file and line number where the error message was found,
	// e.g., "test/e2e/suite/secrettemplate/secrettemplate.go:202".
	ErrLocation string `json:"errLocation"`
}

var CLI struct {
	ParseLogs struct {
		Output    string `output:" Output format." short:"o" default:"text" enum:"text,json"`
		FileOrURL string `arg:"" help:"Log file or URL to be parsed for Ginkgo blocks."`
	} `cmd:"" help:"Parse a build-log.txt file that contains Ginkgo output."`

	MaxDuration struct {
		Output string `output:" Output format." short:"o" default:"text" enum:"text,json"`
		Limit  int    `help:"Limit the number of PRs for which we fetch the logs in the GCS bucket." default:"20"`
	} `cmd:"" help:"Prints the maximum 'passed' duration vs. maximum 'failed' duration of each test. The logs are fetched from the bucket."`
}

func main() {
	kongctx := kong.Parse(&CLI)
	switch kongctx.Command() {
	case "parse-logs <file-or-url>":
		var bytes []byte
		var err error
		if strings.HasPrefix(CLI.ParseLogs.FileOrURL, "http://") || strings.HasPrefix(CLI.ParseLogs.FileOrURL, "https://") {
			content, err := http.Get(CLI.ParseLogs.FileOrURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "fetching URL: %v\n", err)
			}
			bytes, err = ioutil.ReadAll(content.Body)
			if err != nil {
				fmt.Fprintf(os.Stderr, "reading HTTP response: %v\n", err)
			}

			if content.StatusCode != 200 {
				fmt.Fprintf(os.Stderr, "fetching URL: %s: %v\n", content.Status, string(bytes))
			}
		} else {
			bytes, err = ioutil.ReadFile(CLI.ParseLogs.FileOrURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
		}

		blocks, err := parseBuildLog(bytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: while parsing %s: %v\n", CLI.ParseLogs.FileOrURL, err)
			os.Exit(1)
		}

		var results []ginkgoResult
		for _, block := range blocks {
			res, err := parseGinkgoBlock(block)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: parsing one of the ginkgo blocks: %v\n", err)
			}
			results = append(results, res)
		}

		sort.Slice(results, func(i, j int) bool {
			return strings.Compare(results[i].Name, results[j].Name) < 0
		})

		switch CLI.ParseLogs.Output {
		case "json":
			err = json.NewEncoder(os.Stdout).Encode(results)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
		case "text":
			for _, res := range results {
				switch res.Status {
				case statusPassed:
					fmt.Printf("%s\t%s\n", green(res.Duration.String()), res.Name)
				case statusFailed:
					fmt.Printf("%s\t%s: %s\n", red(res.Duration.String()), res.Name, res.Err)
				}
			}
		default:
			fmt.Fprintf(os.Stderr, "developer mistake, defined in kong's enum but not handled: %q\n", CLI.ParseLogs.Output)
			os.Exit(1)
		}

	case "max-duration":
		err := runMaxDurationStats(CLI.MaxDuration.Output, CLI.MaxDuration.Limit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		panic(kongctx.Command())
	}
}

func runMaxDurationStats(output string, limitPRs int) error {
	gcs, err := storage.NewClient(context.Background())
	if err != nil {
		return fmt.Errorf("failed to create GCS client: %v", err)
	}
	bucket := gcs.Bucket("jetstack-logs")

	testcases, err := fetchGinkgoResults(bucket, limitPRs)
	if err != nil {
		return fmt.Errorf("failed to fetch testcases: %v", err)
	}

	stats := computeStatsMaxDuration(testcases)
	switch output {
	case "json":
		err = json.NewEncoder(os.Stdout).Encode(stats)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
		}
	case "text":
		for _, stat := range stats {
			fmt.Printf("%s\t%s\t%s\n",
				green(stat.MaxDurationSuccess.Truncate(1*time.Second).String()),
				red(stat.MaxDurationFailed.Truncate(1*time.Second).String()),
				stat.Name,
			)
		}
	}

	return nil
}

// One ginkgo block looks like this:
//
//   • Failure [301.437 seconds]                          ^
//   [Conformance] Certificates                           |
//   test/e2e/framework/framework.go:287                  |
//     with issuer type External ClusterIssuer            |
//     test/e2e/suite/conformance/certificates.go:47      |
//       should issue a cert with wildcard DNS Name [It]  |
//       test/e2e/suite/conformance/certificates.go:105   |
//       Unexpected error:                                |
//                                                        | "lines"
//           <*errors.errorString | 0xc0001c07b0>: {      |
//               s: "timed out waiting for the condition",|
//           }                                            |
//           timed out waiting for the condition          |
//       occurred                                         |
//       test/e2e/suite/conformance/certificates.go:522   |
//   ------------------------------                       v
type ginkgoBlock struct {
	// Line number of the first line of the Ginkgo block as it appears in the
	// build-log.txt file.
	line int

	// The lines of the ginkgo block, which starts with the line that starts with
	// '• Failure [301.437 seconds]'. It does not include the ending marker
	// '------------------------------'.
	lines []string
}

// The function parseBuildLog parses the content of a build-log.txt file and
// returns a slice of "ginkgo blocks". You don't need to remove ANSI color codes
// that are printed by Ginkgo before giving the logs to this function.
func parseBuildLog(buildLog []byte) ([]ginkgoBlock, error) {
	// Since Ginkgo colors its output, we need to remove the ANSI escape codes.
	rmAnsiColors := regexp.MustCompile(`\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]`)
	buildLog = rmAnsiColors.ReplaceAll(buildLog, []byte(""))

	var blocks []ginkgoBlock
	scanner := bufio.NewScanner(bytes.NewReader(buildLog))
	lineNo := 0
	isContent := false
	var body []string
	for scanner.Scan() {
		lineNo++
		line := scanner.Bytes()
		if !isContent && bytes.HasPrefix(line, []byte("• Failure")) {
			isContent = true
		}

		if isContent {
			body = append(body, string(line))
		}

		if isContent && bytes.Equal(line, []byte("------------------------------")) {
			blocks = append(blocks, ginkgoBlock{
				line:  lineNo,
				lines: body,
			})
			body = nil
			isContent = false
		}
	}

	if isContent {
		return nil, fmt.Errorf("unexpected end of file, still waiting for the ginkgo block started at line %d to end with '------------------------------'", lineNo)
	}

	return blocks, nil
}

var reGingkoBlockHeader = regexp.MustCompile(`• Failure \[(\d+)\.\d+ `)

// The parseGinkgoBlock function parses the body of one ginkgo block, as defined
// in the diagram above the ginkgoBlock struct.
//
// Note that the "[It]" suffixes are removed from the test names in order to
// match the test name given in junit__0x.xml files.
func parseGinkgoBlock(block ginkgoBlock) (ginkgoResult, error) {
	if len(block.lines) < 2 {
		return ginkgoResult{}, fmt.Errorf("a ginkgo block is at least 2 lines long, got: %s", strings.Join(block.lines, "\n"))
	}

	// • Failure [301.574 seconds]                          <- Header
	// [Conformance] Certificates                            ^
	// test/e2e/framework/framework.go:287                   |
	//   with issuer type SelfSigned ClusterIssuer           | Name
	//   test/e2e/suite/conformance/tests.go:47              |
	//     should issue an ECDSA, defaulted cert [It]        |
	//     test/e2e/suite/conformance/suite.go:105           v
	//                                                                 ^
	//     Unexpected error:                                 ^         |
	//         <*errors.errorString | 0xc0001c07d0>: {       |         |
	//             s: "timed out waiting for the condition", | Err     |
	//         }                                             |         | optional
	//         timed out waiting for the condition           |         |
	//     occurred                                          V         |
	//                                                                 |
	//     test/e2e/suite/conformance/tests.go:149          <- ErrLoc  v
	// ------------------------------                       <- Footer

	// Header.
	match := reGingkoBlockHeader.FindStringSubmatch(block.lines[0])
	if len(match) != 2 {
		return ginkgoResult{}, fmt.Errorf("ginkgo block header: expected %s, got: %s", reGingkoBlockHeader, block.lines[0])
	}
	seconds, err := strconv.Atoi(match[1])
	if err != nil {
		return ginkgoResult{}, fmt.Errorf("ginkgo block header: expected an integer, got: %s", match[1])
	}

	duration := time.Duration(seconds) * time.Second

	// Footer.
	if block.lines[len(block.lines)-1] != "------------------------------" {
		return ginkgoResult{}, fmt.Errorf("expected the last line to be '------------------------------', block was: %s", strings.Join(block.lines, "\n"))
	}

	block.lines = block.lines[1 : len(block.lines)-1]

	// Name.
	var parts []string
	i := 0
	for i < len(block.lines)-1 &&
		strings.HasPrefix(block.lines[i], strings.Repeat(" ", i)) &&
		strings.HasPrefix(block.lines[i+1], strings.Repeat(" ", i)) {

		parts = append(parts, strings.TrimPrefix(strings.TrimSuffix(block.lines[i], " [It]"), strings.Repeat(" ", i)))

		i += 2
	}
	if i == 0 {
		return ginkgoResult{}, fmt.Errorf("no name line found, remaining was: %s", strings.Join(block.lines, "\n"))
	}

	name := strings.Join(parts, " ")

	// The Err and ErrLoc are optional.
	if i >= len(block.lines) {
		return ginkgoResult{
			Duration: duration,
			Name:     name,
			Status:   statusFailed,
		}, nil
	}

	indent := strings.Repeat(" ", i-2)

	block.lines = block.lines[i:]
	if block.lines[0] == "" {
		block.lines = block.lines[1:]
	}

	// Now, let's remove the indentation of Err and ErrLoc.
	for j := range block.lines {
		block.lines[j] = strings.TrimPrefix(block.lines[j], indent)
	}

	// ErrLoc.
	errLoc := strings.TrimPrefix(block.lines[len(block.lines)-1], indent)

	// Err.
	// The "-2" skips the ErrLoc and the blank line between the Err and ErrLoc.
	block.lines = block.lines[0 : len(block.lines)-2]

	// Now let's deal with this overly verbose "Unexpected error... occurred" that looks like this:
	//
	//  Unexpected error:
	//      <*errors.errorString | 0xc0001c07d0>: {
	//          s: "timed out waiting for the condition",
	//      }
	//      timed out waiting for the condition
	//  occurred
	//
	// Notice the indentation (4 spaces).
	if block.lines[0] == "Unexpected error:" {
		for i := range block.lines {
			if !isParen.MatchString(block.lines[i]) {
				continue
			}
			block.lines = block.lines[i+1 : len(block.lines)-1]
			break
		}
		for i := range block.lines {
			block.lines[i] = strings.TrimPrefix(block.lines[i], "    ")
		}
	}

	errStr := strings.Join(block.lines, "\n")

	return ginkgoResult{
		Duration:    duration,
		Name:        name,
		Status:      statusFailed,
		Err:         errStr,
		ErrLocation: errLoc,
	}, nil
}

var isParen = regexp.MustCompile(" *}$")

// Beware the duplicates!! One test case for a given job may appear in both a
// junit file and in the build-log.txt. We do not de-duplicate them at the
// moment.
//
// This function prints two progress bars: one for for fetching the objects
// (just the attributes), and then a bar to download the XML and build-log.txt
// files.
func fetchGinkgoResults(bucket *storage.BucketHandle, numberPastPRs int) ([]ginkgoResult, error) {
	bar := progressbar.NewOptions(int(10 /* seconds */ *5 /* =1/200ms */),
		progressbar.OptionSetPredictTime(false),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(false),
		progressbar.OptionSetDescription("Listing all PRs..."),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)
	_ = bar.RenderBlank()
	go func() {
		for !bar.IsFinished() {
			time.Sleep(200 * time.Millisecond)
			_ = bar.Add(1)
			_ = bar.RenderBlank()
		}
	}()
	prPrefixes, err := listPRPrefixes(bucket, "pr-logs/pull/jetstack_cert-manager")
	if err != nil {
		return nil, fmt.Errorf("failed to list PR prefixes: %v", err)
	}
	_ = bar.Clear()
	_ = bar.Finish()

	// There may be a lot of PRs; for example, we 20 PRs selected, prowdig will
	// download around 600MB of build-log.txt.
	if len(prPrefixes) > numberPastPRs {
		prPrefixes = prPrefixes[len(prPrefixes)-numberPastPRs:]
	}

	isJunitFile := regexp.MustCompile(`junit__.*\.xml$`)
	isBuildLogFile := regexp.MustCompile(`build-log\.txt$`)
	isJunitOrBuildLog := regexp.MustCompile("(" + isJunitFile.String() + "|" + isBuildLogFile.String() + ")")

	// For each PR prefix such as pr-logs/pull/jetstack_cert-manager/4664/,
	// we fetch all the junit files and build-log.txt files.
	objects, totalSize, err := listObjectsUnderPrefixes(bucket, prPrefixes, isJunitOrBuildLog)
	if err != nil {
		return nil, fmt.Errorf("failed to list objects under prefixes: %v", err)
	}

	bar = progressbar.NewOptions64(totalSize,
		progressbar.OptionSetPredictTime(true),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetDescription("Downloading logs for each job..."),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)
	_ = bar.RenderBlank()
	var ginkgoResults []ginkgoResult
	for _, object := range objects {
		bytes, err := fetchObject(&object, bucket)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch %s: %w", object.Name, err)
		}
		_ = bar.Add64(object.Size)

		switch {
		case isJunitFile.MatchString(object.Name):
			parsed, err := parseJunit(bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse junit file %s: %w", object.Name, err)
			}
			ginkgoResults = append(ginkgoResults, parsed...)
		case isBuildLogFile.MatchString(object.Name):
			blocks, err := parseBuildLog(bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse build-log.txt file %s: %w", object.Name, err)
			}

			for _, block := range blocks {
				testcase, err := parseGinkgoBlock(block)
				if err != nil {
					return nil, fmt.Errorf("failed to parse ginkgo block at line %d: %w", block.line, err)
				}
				ginkgoResults = append(ginkgoResults, testcase)
			}
		default:
			return nil, fmt.Errorf("developer mistake: expected name %s but got %s", isJunitOrBuildLog.String(), object.Name)
		}
	}
	_ = bar.Clear()
	_ = bar.Finish()

	return ginkgoResults, nil
}

type StatsMaxDuration struct {
	Name               string
	MaxDurationSuccess time.Duration
	MaxDurationFailed  time.Duration
}

func computeStatsMaxDuration(testcases []ginkgoResult) []StatsMaxDuration {
	type max struct {
		success time.Duration
		failed  time.Duration
	}

	// The key is the test name.
	maxMap := make(map[string]max)

	var testNames []string
	for _, testcase := range testcases {
		if _, ok := maxMap[testcase.Name]; !ok {
			testNames = append(testNames, testcase.Name)
			maxMap[testcase.Name] = max{success: 0, failed: 0}
		}
		cur := maxMap[testcase.Name]
		switch testcase.Status {
		case statusPassed:
			if cur.success < testcase.Duration {
				cur.success = testcase.Duration
			}
		case statusFailed:
			if cur.failed < testcase.Duration {
				cur.failed = testcase.Duration
			}
		}
		maxMap[testcase.Name] = cur
	}

	// If there has been no failure, then we cannot say anything about the
	// timeout. So we filter out the tests that have no failure.
	var testNamesFiltered []string
	for _, name := range testNames {
		if maxMap[name].failed == 0 {
			continue
		}
		testNamesFiltered = append(testNamesFiltered, name)
	}
	testNames = testNamesFiltered

	// We want to see the test cases for which the
	sort.Slice(testNames, func(i, j int) bool {
		return maxMap[testNames[i]].failed-maxMap[testNames[i]].success < maxMap[testNames[j]].failed-maxMap[testNames[j]].success
	})

	var stats []StatsMaxDuration
	for _, name := range testNames {
		stats = append(stats, StatsMaxDuration{
			Name:               name,
			MaxDurationSuccess: maxMap[name].success,
			MaxDurationFailed:  maxMap[name].failed,
		})
	}
	return stats
}

// Returns the objects (just their attributes) that match the given regex across
// all the prefixes given in input, as well as the total size in bytes.
//
// A progress bar is shown since there are many calls made to GCS and it takes a
// few seconds.
//
// For example, with:
//
//  listObjectsUnderPrefixes(bucket, []string{
//    "pr-logs/pull/jetstack_cert-manager/1016/",
//    "pr-logs/pull/jetstack_cert-manager/1017/",
//  }, regexp.MustCompile(`(build-log\.txt|junit__.*\.xml)$`))
//
// the returned object.Name will be:
//
//   pr-logs/pull/jetstack_cert-manager/1016/pull-cert-manager-e2e-v1-13/231/build-log.txt
//   pr-logs/pull/jetstack_cert-manager/1016/pull-cert-manager-e2e-v1-13/231/artifacts/junit__01.xml
//   pr-logs/pull/jetstack_cert-manager/1016/pull-cert-manager-e2e-v1-13/231/artifacts/junit__02.xml
//   pr-logs/pull/jetstack_cert-manager/1016/pull-cert-manager-e2e-v1-13/231/artifacts/junit__10.xml
//   pr-logs/pull/jetstack_cert-manager/1017/pull-cert-manager-e2e-v1-13/231/build-log.txt
//   pr-logs/pull/jetstack_cert-manager/1017/pull-cert-manager-e2e-v1-13/231/artifacts/junit__01.xml
//   pr-logs/pull/jetstack_cert-manager/1017/pull-cert-manager-e2e-v1-13/231/artifacts/junit__02.xml
//   pr-logs/pull/jetstack_cert-manager/1017/pull-cert-manager-e2e-v1-13/231/artifacts/junit__10.xml
//   <----------- prPrefix ----------------->
func listObjectsUnderPrefixes(bucket *storage.BucketHandle, prPrefixes []string, only *regexp.Regexp) ([]storage.ObjectAttrs, int64, error) {
	var objects []storage.ObjectAttrs
	totalSize := int64(0)

	bar := progressbar.NewOptions(len(prPrefixes),
		progressbar.OptionSetPredictTime(true),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(false),
		progressbar.OptionSetDescription("Listing jobs for each PR prefix..."),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)
	_ = bar.RenderBlank()
	defer func() {
		_ = bar.Clear()
		_ = bar.Finish()
	}()

	for _, prPrefix := range prPrefixes {
		objectIter := bucket.Objects(context.Background(), &storage.Query{
			Prefix: prPrefix, Projection: storage.ProjectionNoACL,
		})

		for {
			object, err := objectIter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return nil, 0, fmt.Errorf("failed to iterate over GCS objects: %s: %w", object.Name, err)
			}

			if !only.MatchString(object.Name) {
				continue
			}

			totalSize += object.Size

			// Why "*object"? No one else is going to touch the
			// *storage.ObjectAttrs pointer, so it makes sense to do a shallow
			// copy here since all the "shared" fields like object.Metadata
			// won't be used by anyone else.
			objects = append(objects, *object)
		}
		_ = bar.Add(1)
	}
	return objects, totalSize, nil
}

// The "skipped" tests are not taken into account. Only the "failed", "error"
// and "passed" are dealt with.
func parseJunit(bytes []byte) ([]ginkgoResult, error) {
	suites, err := junit.Ingest(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to ingest junit XML: %w", err)
	}

	var testcases []ginkgoResult
	for _, suite := range suites {
		for _, test := range suite.Tests {
			var s status
			switch test.Status {
			case "passed":
				s = statusPassed
			case "failed", "error":
				s = statusFailed
			case "skipped":
				continue
			}

			testcases = append(testcases, ginkgoResult{
				Duration: test.Duration,
				Status:   s,
				Name:     test.Name,
			})
		}
	}
	return testcases, nil
}

// Returns the numerically ordered pull request prefixes. Prefixes that do not
// end with a number are skipped. The prefix string corresponds to the string
// that you would give to gsutil in order to list all the PRs; the ending "/" is
// optional:
//
//  gsutil ls gs://jetstack-logs/pr-logs/pull/jetstack_cert-manager
//                 <--bucket---> <----------- prefix ------------->
//
// The returned strings are numerically ordered and look like this:
//
//  pr-logs/pull/jetstack_cert-manager/1/
//  pr-logs/pull/jetstack_cert-manager/2/
//  pr-logs/pull/jetstack_cert-manager/10/
//  pr-logs/pull/jetstack_cert-manager/20/
//  <----------- prefix ------------->
func listPRPrefixes(bucket *storage.BucketHandle, prefix string) ([]string, error) {
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	endsWithPRNumber := regexp.MustCompile(`/(\d+)/$`)

	prIter := bucket.Objects(context.Background(), &storage.Query{
		Prefix: prefix, Delimiter: "/", Projection: storage.ProjectionNoACL,
	})

	var prPrefixes []string
	for {
		pr, err := prIter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to iterate over GCS objects: %v", err)
		}

		if !endsWithPRNumber.MatchString(pr.Prefix) {
			continue
		}

		prPrefixes = append(prPrefixes, pr.Prefix)
	}

	// Sorting with strings.Compare would yield a lexicographical order of the
	// prPrefixes, it would look like this::
	//
	//  pr-logs/pull/jetstack_cert-manager/1/
	//  pr-logs/pull/jetstack_cert-manager/10/
	//  pr-logs/pull/jetstack_cert-manager/2/    <-- wrong
	//  pr-logs/pull/jetstack_cert-manager/20/
	//
	// Instead, we want a numerical ordering:
	//
	//  pr-logs/pull/jetstack_cert-manager/1/
	//  pr-logs/pull/jetstack_cert-manager/2/    <-- right
	//  pr-logs/pull/jetstack_cert-manager/10/
	//  pr-logs/pull/jetstack_cert-manager/20/
	sort.Slice(prPrefixes, func(i, j int) bool {
		matches := endsWithPRNumber.FindStringSubmatch(prPrefixes[i])
		if len(matches) != 2 {
			return true
		}

		int1, err := strconv.Atoi(matches[1])
		if err != nil {
			panic("developer mistake: " + err.Error())
		}

		matches = endsWithPRNumber.FindStringSubmatch(prPrefixes[j])
		if len(matches) != 2 {
			return false
		}

		int2, err := strconv.Atoi(matches[1])
		if err != nil {
			panic("developer mistake: " + err.Error())
		}

		return int1 < int2
	})

	return prPrefixes, nil
}

// fetchObject fetches the object from GCS and stores it in ~/.cache/prowdig/.
// If the object is already in the cache and its CRC32 sum matches the one in
// GCS, the cached object is returned. If the CRC32 sum does not match, the
// object is re-downloaded.
func fetchObject(file *storage.ObjectAttrs, bucket *storage.BucketHandle) ([]byte, error) {
	var bytes []byte
	cachedFile := os.Getenv("HOME") + "/.cache/prowdig/" + file.Name
	if _, err := os.Stat(cachedFile); err == nil {
		bytes, err = ioutil.ReadFile(os.Getenv("HOME") + "/.cache/prowdig/" + file.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to read from cache: %s: %w", file.Name, err)
		}

		if crc32.Checksum(bytes, crc32.MakeTable(crc32.Castagnoli)) == file.CRC32C {
			// We have hit the cache!
			return bytes, nil
		}

		fmt.Fprintf(os.Stderr, "warning: checksum for cache file %s does not match, it will be re-downloaded\n", cachedFile)
	}

	reader, err := bucket.Object(file.Name).NewReader(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to read GCS object: %s: %w", file.Name, err)
	}

	bytes, err = ioutil.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read GCS object: %s: %w", file.Name, err)
	}

	err = os.MkdirAll(path.Dir(cachedFile), 0755)
	if err != nil {
		return nil, fmt.Errorf("failed to create cache dir: %w", err)
	}

	err = ioutil.WriteFile(cachedFile, bytes, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to write to cache: %s: %w", file.Name, err)
	}

	return bytes, nil
}

func green(s string) string {
	return fmt.Sprintf("\x1b[32m%s\x1b[0m", s)
}
func red(s string) string {
	return fmt.Sprintf("\x1b[31m%s\x1b[0m", s)
}
