package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/ioutil"
	"math"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"cloud.google.com/go/storage"
	"github.com/alecthomas/kong"
	"github.com/fatih/color"
	"github.com/joshdk/go-junit"
	"github.com/mattn/go-isatty"
	pb "github.com/schollz/progressbar/v3"
	"google.golang.org/api/iterator"
)

var (
	bucketName     = "jetstack-logs"
	bucketPrefixes = []string{"pr-logs/pull/jetstack_cert-manager", "pr-logs/pull/cert-manager_cert-manager"}
	cacheDir       = os.Getenv("HOME") + "/.cache/prowdig/" + bucketName

	endsWithPRNumber    = regexp.MustCompile(`/(\d+)/?$`)
	rmAnsiColors        = regexp.MustCompile(`\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]`)
	reGingkoBlockHeader = regexp.MustCompile(`• (Failure|Failure in Spec Setup.*) \[(\d+)\.\d+ `)
	isParen             = regexp.MustCompile(" *}$")
	isJunitFile         = regexp.MustCompile(`junit__.*\.xml$`)
	isBuildLogFile      = regexp.MustCompile(`build-log\.txt$`)
	isToBeDownloaded    = regexp.MustCompile("(" + isJunitFile.String() + "|" + isBuildLogFile.String() + ")")
	reObjectName        = regexp.MustCompile(`/(\d+)\/([^\/]+)\/(\d+)\/`)

	red   = color.New(color.FgRed).SprintFunc()
	green = color.New(color.FgGreen).SprintFunc()
	blue  = color.New(color.FgBlue).SprintFunc()
	gray  = color.New(color.FgHiBlack).SprintFunc()

	theme = pb.Theme{Saucer: "[green]=[reset]", SaucerHead: "[green]>[reset]", SaucerPadding: " ", BarStart: "[", BarEnd: "]"}
)

type status string

const (
	statusPassed status = "passed"
	statusFailed status = "failed"

	// When the test setup failed, e.g. during BeforeEach.
	statusError status = "error"
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

	// The Duration of the test case in seconds.
	Duration int `json:"duration"`

	// (optional) The error message shown right before the keyword 'occurred' at
	// the bottom of the ginkgo block.
	Err string `json:"err"`

	// (optional) The Go file and line number where the error message was found,
	// e.g., "test/e2e/suite/secrettemplate/secrettemplate.go:202".
	ErrLoc string `json:"errLoc"`

	// (optional) The file path or URL to the build-log.txt file where this
	// error was found. Will be either:
	//
	//
	// https://storage.googleapis.com/jetstack-logs/pr-logs/pull/.../build-log.txt
	Source string `json:"source"`

	// (optional) The name of the Prow job.
	Job string `json:"job"`

	// (optional) The PR number.
	PR int `json:"pr"`

	// (optional) The Prow job build number.
	Build int `json:"build"`
}

var CLI struct {
	Tests struct {
		Output    string `help:"Output format. Can be either 'text' or 'json'." short:"o" default:"text" enum:"text,json"`
		ParseLogs struct {
			FileOrURL string `arg:"" help:"Log file or URL to be parsed for Ginkgo blocks."`
		} `cmd:"" help:"Parse the Ginkgo failure blocks from a given file or URL."`

		List struct {
			Limit      int    `help:"Limit the number of PRs for which we fetch the logs in the GCS bucket." default:"20"`
			Name       string `help:"Only list tests for which the name contains the given string."`
			OnlyFailed bool   `help:"Hide tests that have the status 'passed' or 'error'."`
		} `cmd:"" help:"Lists all the test results ordered by name. The logs are fetched from the bucket."`

		MaxDuration struct {
			Limit      int  `help:"Limit the number of PRs for which we fetch the logs in the GCS bucket." default:"20"`
			NoDownload bool `help:"Only use the local cache, do not download anything from the GCS bucket."`
		} `cmd:"" help:"Lists the maximum 'passed' duration vs. maximum 'failed' duration of each test order by name. The logs are fetched from the bucket."`

		MostFailures struct {
			Limit      int  `help:"Limit the number of PRs for which we fetch the logs in the GCS bucket." default:"20"`
			NoDownload bool `help:"Only use the local cache, do not download anything from the GCS bucket."`
		} `cmd:"" help:"Lists the test names that fail the most. Two numbers are shown: the count of passed and the count of failed tests. The last error message is shown right after the test name. The list is sorted in descending order by the count of failed tests."`
	} `cmd:"" help:"Everything related to individual test cases."`

	Jobs struct {
		Output string `help:"Output format. Can be either 'text' or 'json'." short:"o" default:"text" enum:"text,json"`
		List   struct {
			Limit int `help:"Limit the number of PRs for which we fetch the logs in the GCS bucket." default:"20"`
		} `cmd:"" help:"Lists all the jobs."`
	} `cmd:"" help:"Everything related to jobs."`
	NoDownload bool   `help:"If a command is meant to fetch from GCS, only use the local cache, do not download anything."`
	Color      string `help:"Change the coloring behavior. Can be one of auto, never, or always." enum:"auto,never,always" default:"auto"`
}

func main() {
	kongctx := kong.Parse(&CLI)

	switch CLI.Color {
	case "auto":
		color.NoColor = os.Getenv("TERM") == "dumb" || !isatty.IsTerminal(os.Stdout.Fd())
	case "never":
		color.NoColor = true
	case "always":
		color.NoColor = false
	}

	switch kongctx.Command() {
	case "tests parse-logs <file-or-url>":
		var bytes []byte
		var err error
		isURL := strings.HasPrefix(CLI.Tests.ParseLogs.FileOrURL, "http://") || strings.HasPrefix(CLI.Tests.ParseLogs.FileOrURL, "https://")
		if isURL {
			content, err := http.Get(CLI.Tests.ParseLogs.FileOrURL)
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
			bytes, err = ioutil.ReadFile(CLI.Tests.ParseLogs.FileOrURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
		}

		blocks, err := parseBuildLog(bytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: while parsing %s: %v\n", CLI.Tests.ParseLogs.FileOrURL, err)
			os.Exit(1)
		}

		// We don't use the syntax 'var results' so that the encoded JSON shows
		// "[]" instead of "null".
		results := []ginkgoResult{}
		for _, block := range blocks {
			parsed, err := parseGinkgoBlock(block)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: parsing one of the ginkgo blocks: %v\n", err)
			}

			source := CLI.Tests.ParseLogs.FileOrURL + ":" + strconv.Itoa(block.line)
			if isURL {
				source = CLI.Tests.ParseLogs.FileOrURL + "#line=" + strconv.Itoa(block.line)
			}

			results = append(results, ginkgoResult{
				Name:     parsed.name,
				Status:   parsed.status,
				Duration: parsed.duration,
				Err:      parsed.errStr,
				ErrLoc:   parsed.errLoc,
				Source:   source,
				Job:      "",
				PR:       0,
				Build:    0,
			})
		}

		sort.Slice(results, func(i, j int) bool {
			return strings.Compare(results[i].Name, results[j].Name) < 0
		})

		switch CLI.Tests.Output {
		case "json":
			err = json.NewEncoder(os.Stdout).Encode(results)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
		case "text":
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.TabIndent)
			defer w.Flush()

			for _, res := range results {
				duration := (time.Duration(res.Duration) * time.Second).String()
				switch res.Status {
				case statusPassed:
					fmt.Fprintf(w, "✅ %s\t%s\n", green(duration), res.Name)
				case statusFailed:
					fmt.Fprintf(w, "❌ %s\t%s: %s\n", red(duration), res.Name, res.Err)
				case statusError:
					fmt.Fprintf(w, "💣️ %s\t%s: %s\n", blue(duration), res.Name, res.Err)
				default:
					panic("developer mistake: unknown status: " + res.Status)
				}
			}
		default:
			fmt.Fprintf(os.Stderr, "developer mistake, defined in kong's enum but not handled: %q\n", CLI.Tests.Output)
			os.Exit(1)
		}

	case "tests max-duration":
		if !CLI.NoDownload {
			err := downloadBuildArtifactsToCache(bucketName, CLI.Tests.List.Limit, isToBeDownloaded)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to download job artifacts: %v\n", err)
				os.Exit(1)
			}
		}

		results, err := parseGinkgoResultsFromCache(bucketName, bucketPrefixes, CLI.Tests.MaxDuration.Limit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to fetch ginkgo results from files: %v\n", err)
			os.Exit(1)
		}

		stats := computeStatsMaxDuration(results)
		switch CLI.Tests.Output {
		case "json":
			if stats == nil {
				// Force the encoded JSON to show "[]" instead of "null".
				stats = []StatsMaxDuration{}
			}
			err = json.NewEncoder(os.Stdout).Encode(stats)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
			}
		case "text":
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.TabIndent)
			defer w.Flush()

			for _, stat := range stats {
				fmt.Fprintf(w, "%s\t%s\t%s\n",
					green((time.Duration(stat.MaxDurationPassed) * time.Second).String()),
					red((time.Duration(stat.MaxDurationFailed) * time.Second).String()),
					stat.Name,
				)
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

	case "tests most-failures":
		if !CLI.NoDownload {
			err := downloadBuildArtifactsToCache(bucketName, CLI.Tests.MostFailures.Limit, isToBeDownloaded)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to download job artifacts: %v\n", err)
				os.Exit(1)
			}
		}

		results, err := parseGinkgoResultsFromCache(bucketName, bucketPrefixes, CLI.Tests.MostFailures.Limit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to fetch ginkgo results from files: %v\n", err)
			os.Exit(1)
		}

		stats := computeStatsMostFailures(results)
		switch CLI.Tests.Output {
		case "json":
			if stats == nil {
				// Force the encoded JSON to show "[]" instead of "null".
				stats = []StatsMostFailures{}
			}
			err = json.NewEncoder(os.Stdout).Encode(stats)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
			}
		case "text":
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.TabIndent)
			defer w.Flush()

			for _, stat := range stats {
				lastErr := ""
				if len(stat.Errors) > 0 {
					lastErr = stat.Errors[len(stat.Errors)-1]
				}
				fmt.Fprintf(w, "%s\t%s\t%s: %s\n",
					green(stat.CountPassed),
					red(stat.CountFailed),
					stat.Name,
					gray(lastErr),
				)
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

	case "tests list":
		if !CLI.NoDownload {
			err := downloadBuildArtifactsToCache(bucketName, CLI.Tests.List.Limit, isToBeDownloaded)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to download job artifacts: %v\n", err)
				os.Exit(1)
			}
		}

		results, err := parseGinkgoResultsFromCache(bucketName, bucketPrefixes, CLI.Tests.List.Limit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to fetch ginkgo results from files: %v\n", err)
			os.Exit(1)
		}

		var filtered []ginkgoResult
		for _, res := range results {
			if !strings.Contains(res.Name, CLI.Tests.List.Name) {
				continue
			}

			if CLI.Tests.List.OnlyFailed && res.Status != statusFailed {
				continue
			}

			filtered = append(filtered, res)
		}
		results = filtered

		sort.Slice(results, func(i, j int) bool {
			return strings.Compare(results[i].Name, results[j].Name) < 0
		})

		switch CLI.Tests.Output {
		case "json":
			if results == nil {
				// Force the encoded JSON to show "[]" instead of "null".
				results = []ginkgoResult{}
			}
			err = json.NewEncoder(os.Stdout).Encode(results)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
			}
		case "text":
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.TabIndent)
			defer w.Flush()

			for _, res := range results {
				switch res.Status {
				case statusPassed:
					fmt.Fprintf(w, "✅ %s\t%s\n", green((time.Duration(res.Duration) * time.Second).String()), res.Name)
				case statusFailed:
					fmt.Fprintf(w, "❌ %s\t%s: %s\n", red((time.Duration(res.Duration) * time.Second).String()), res.Name, res.Err)
				case statusError:
					fmt.Fprintf(w, "💣️ %s\t%s: %s\n", blue((time.Duration(res.Duration) * time.Second).String()), res.Name, res.Err)
				default:
					panic("developer mistake: unknown status: " + res.Status)
				}
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

	case "jobs list":
		if !CLI.NoDownload {
			err := downloadBuildArtifactsToCache(bucketName, CLI.Jobs.List.Limit, regexp.MustCompile(`prowjob\.json$`))
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to download build artifacts: %v\n", err)
				os.Exit(1)
			}
		}

		results, err := parseBuildsFromCache(bucketPrefixes, CLI.Jobs.List.Limit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to fetch build results from files: %v\n", err)
			os.Exit(1)
		}

		switch CLI.Jobs.Output {
		case "json":
			if results == nil {
				// Force the encoded JSON to show "[]" instead of "null".
				results = []BuildResult{}
			}
			err = json.NewEncoder(os.Stdout).Encode(results)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
			}
		case "text":
			for _, res := range results {
				switch res.Status {
				case BuildSuccess:
					fmt.Printf("%s\t%s\n", green((time.Duration(res.Duration) * time.Second).String()), res.JobName)
				case BuildFailed:
					fmt.Printf("%s\t%s: %s\n", red((time.Duration(res.Duration) * time.Second).String()), res.JobName, res.Err)
				default:
					panic("developer mistake: unknown status: " + res.Status)
				}
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

	default:
		panic("developer mistake: " + kongctx.Command())
	}
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

type parsedGinkgoBlock struct {
	// The name of the test.
	name     string
	status   status
	duration int
	errStr   string
	errLoc   string
}

// The parseGinkgoBlock function parses the body of one ginkgo block, as defined
// in the diagram above the ginkgoBlock struct.
//
// Note that the "[It]" suffixes are removed from the test names in order to
// match the test name given in junit__0x.xml files.
func parseGinkgoBlock(block ginkgoBlock) (parsedGinkgoBlock, error) {
	if len(block.lines) < 2 {
		return parsedGinkgoBlock{}, fmt.Errorf("a ginkgo block is at least 2 lines long, got: %s", strings.Join(block.lines, "\n"))
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
	if len(match) != 3 {
		return parsedGinkgoBlock{}, fmt.Errorf("ginkgo block header: expected %s, got: %s", reGingkoBlockHeader, block.lines[0])
	}

	var status status
	switch {
	case strings.HasPrefix(match[1], "Failure in Spec Setup"):
		status = statusError
	case match[1] == "Failure":
		status = statusFailed
	default:
		return parsedGinkgoBlock{}, fmt.Errorf("ginkgo block header: expected 'Failure' or 'Failure in Spec Setup', got: %s", match[1])
	}

	duration, err := strconv.Atoi(match[2])
	if err != nil {
		return parsedGinkgoBlock{}, fmt.Errorf("ginkgo block header: expected an integer, got: %s", match[1])
	}

	// Footer.
	if block.lines[len(block.lines)-1] != "------------------------------" {
		return parsedGinkgoBlock{}, fmt.Errorf("expected the last line to be '------------------------------', block was: %s", strings.Join(block.lines, "\n"))
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
		return parsedGinkgoBlock{}, fmt.Errorf("no name line found, remaining was: %s", strings.Join(block.lines, "\n"))
	}

	name := strings.Join(parts, " ")

	// The Err and ErrLoc are optional.
	if i >= len(block.lines) {
		return parsedGinkgoBlock{
			name:     name,
			status:   status,
			duration: duration,
			errStr:   "",
			errLoc:   "",
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

	return parsedGinkgoBlock{
		name:     name,
		status:   status,
		duration: duration,
		errStr:   errStr,
		errLoc:   errLoc,
	}, nil
}

// Return a list of object names, e.g.:
//   pr-logs/pull/jetstack_cert-manager/1/pull-cert-manager-e2e-v1-13/232/artifacts/junit__01.xml
//   pr-logs/pull/jetstack_cert-manager/1/pull-cert-manager-e2e-v1-13/232/artifacts/junit__02.xml
//   pr-logs/pull/jetstack_cert-manager/1/pull-cert-manager-e2e-v1-13/232/build-log.txt
//   pr-logs/pull/jetstack_cert-manager/1/pull-cert-manager-e2e-v1-13/232/clone-log.txt
//   pr-logs/pull/jetstack_cert-manager/1/pull-cert-manager-e2e-v1-13/232/clone-records.json
//   pr-logs/pull/jetstack_cert-manager/1/pull-cert-manager-e2e-v1-13/232/finished.json
//   pr-logs/pull/jetstack_cert-manager/1/pull-cert-manager-e2e-v1-13/232/podinfo.json
//   pr-logs/pull/jetstack_cert-manager/1/pull-cert-manager-e2e-v1-13/232/prowjob.json
//   pr-logs/pull/jetstack_cert-manager/1/pull-cert-manager-e2e-v1-13/232/started.json
//   pr-logs/pull/jetstack_cert-manager/2/pull-cert-manager-e2e-v1-13/245/build-log.txt...
//
// The filter can be left nil.
func downloadBuildArtifactsToCache(bucketName string, maxJobs int, filter *regexp.Regexp) error {
	gcs, err := storage.NewClient(context.Background())
	if err != nil {
		return fmt.Errorf("error: Google Cloud storage: %v\n", err)
	}
	bucket := gcs.Bucket(bucketName)

	bar1 := pb.NewOptions(int(5 /* seconds */ *5 /* = 1/200 ms */),
		pb.OptionSetPredictTime(false),
		pb.OptionSetWriter(os.Stderr),
		pb.OptionEnableColorCodes(true),
		pb.OptionShowBytes(false),
		pb.OptionSetDescription("Listing all PRs..."),
		pb.OptionSetTheme(theme),
	)
	go func() {
		for !bar1.IsFinished() {
			_ = bar1.Add(1)
			_ = bar1.RenderBlank()
			time.Sleep(200 * time.Millisecond)
		}
	}()
	prPrefixes, err := listPRPrefixes(bucket, bucketPrefixes)
	if err != nil {
		return fmt.Errorf("failed to list PR prefixes: %v", err)
	}
	_ = bar1.Finish()
	_ = bar1.Clear()

	// Now, let's list the files under each PR prefix.
	var objects []storage.ObjectAttrs
	totalSize := int64(0)

	bar2 := pb.NewOptions(maxJobs,
		pb.OptionSetWriter(os.Stderr),
		pb.OptionSetPredictTime(false),
		pb.OptionEnableColorCodes(true),
		pb.OptionShowBytes(false),
		pb.OptionSetDescription(fmt.Sprintf("Finding the last %d jobs...", maxJobs)),
		pb.OptionSetTheme(theme),
	)
	_ = bar2.RenderBlank()
	countJobs := 0 // One prowjob.json = one build.
	for _, prPrefix := range prPrefixes {
		objectIter := bucket.Objects(context.Background(), &storage.Query{
			Prefix: prPrefix, Projection: storage.ProjectionNoACL,
		})

		for countJobs < maxJobs {
			object, err := objectIter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return fmt.Errorf("failed to iterate over GCS objects: %s: %w", object.Name, err)
			}

			if strings.HasSuffix(object.Name, "prowjob.json") {
				countJobs++
				_ = bar2.Add(1)
			}

			if filter != nil && !filter.MatchString(object.Name) {
				continue
			}

			totalSize += object.Size

			// Why "*object"? No one else is going to touch the
			// *storage.ObjectAttrs pointer, so it makes sense to do a shallow
			// copy here since all the "shared" fields like object.Metadata
			// won't be used by anyone else.
			objects = append(objects, *object)

		}
		if countJobs >= maxJobs {
			break
		}
	}
	_ = bar2.Finish()
	_ = bar2.Clear()

	bar3 := pb.NewOptions64(totalSize,
		pb.OptionSetWriter(os.Stderr),
		pb.OptionSetPredictTime(true),
		pb.OptionShowCount(),
		pb.OptionEnableColorCodes(true),
		pb.OptionShowBytes(true),
		pb.OptionSetDescription("Downloading logs for each job..."),
		pb.OptionSetTheme(theme),
	)
	_ = bar3.RenderBlank()
	for _, object := range objects {
		err := downloadToCache(&object, bucket)
		if err != nil {
			return fmt.Errorf("failed to download jobs artifacts for %s: %w", object.Name, err)
		}
		_ = bar3.Add64(object.Size)
	}
	_ = bar3.Finish()
	_ = bar3.Clear()

	return nil
}

// The "bucket" string in input is used for displaying and logging. It is not
// used to fetch anything from GCS.
func parseGinkgoResultsFromCache(bucketName string, bucketPrefixes []string, maxJobs int) ([]ginkgoResult, error) {
	// Let's only select the last few PRs.
	artifacts, err := findCachedArtifacts(bucketPrefixes, maxJobs)
	if err != nil {
		return nil, fmt.Errorf("failed to find cached artifacts: %v", err)
	}

	bar := pb.NewOptions(len(artifacts),
		pb.OptionSetWriter(os.Stderr),
		pb.OptionSetPredictTime(true),
		pb.OptionShowCount(),
		pb.OptionEnableColorCodes(true),
		pb.OptionShowBytes(false),
		pb.OptionSetDescription("Parsing logs..."),
		pb.OptionSetTheme(theme),
	)
	defer func() {
		_ = bar.Finish()
		_ = bar.Clear()
	}()

	var ginkgoResults []ginkgoResult
	for _, artifact := range artifacts {
		bar.Add(1)

		if !isToBeDownloaded.MatchString(artifact) {
			continue
		}

		bytes, err := loadFromCache(artifact)
		if err != nil {
			return nil, fmt.Errorf("failed to load from file %s, was expected to be already in cache: %w", artifact, err)
		}

		// The url below is meant for the 'source' field as well as for logging
		// purposes.
		// https://storage.googleapis.com/jetstack-logs/<object-name>
		objectName := strings.TrimPrefix(artifact, cacheDir+"/")
		url := "https://storage.googleapis.com/" + bucketName + "/" + objectName
		pr, job, build, err := parseObjectName(objectName)
		if err != nil {
			return nil, fmt.Errorf("parsing object name %s: %w", objectName, err)
		}

		switch {
		case isJunitFile.MatchString(artifact):
			parsedBlocks, err := parseJunit(bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse junit file %s: %w", url, err)
			}

			for _, parsed := range parsedBlocks {
				ginkgoResults = append(ginkgoResults, ginkgoResult{
					Name:     parsed.name,
					Duration: parsed.duration,
					Status:   parsed.status,
					Err:      parsed.errStr,
					ErrLoc:   parsed.errLoc,
					Source:   url, // No line indication for junit files.
					PR:       pr,
					Job:      job,
					Build:    build,
				})
			}

		case isBuildLogFile.MatchString(artifact):
			blocks, err := parseBuildLog(bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse build-log.txt file %s: %w", url, err)
			}

			for _, block := range blocks {
				parsed, err := parseGinkgoBlock(block)
				if err != nil {
					return nil, fmt.Errorf("failed to parse ginkgo block at line %d in %s: %w", block.line, url, err)
				}

				ginkgoResults = append(ginkgoResults, ginkgoResult{
					Name:     parsed.name,
					Duration: parsed.duration,
					Status:   parsed.status,
					Err:      parsed.errStr,
					ErrLoc:   parsed.errLoc,
					Source:   url + "#line=" + strconv.Itoa(block.line),
					PR:       pr,
					Job:      job,
					Build:    build,
				})
			}
		default:
			return nil, fmt.Errorf("developer mistake: expected name %s but got %s", isToBeDownloaded.String(), url)
		}
	}
	return ginkgoResults, nil
}

type BuildStatus string

const (
	BuildSuccess BuildStatus = "success"
	BuildFailed  BuildStatus = "failure"
)

type BuildResult struct {
	// Can be "success" or "failure". We don't care about "pending" states.
	Status BuildStatus `json:"status"`

	// The duration in seconds of this build.
	Duration int `json:"duration"`

	// URL to the Prow UI for this build.
	URL string `json:"url"`

	// Name of the job, e.g. "pull-cert-manager-e2e-v1-13"
	JobName string `json:"jobName"`

	// (optional) Show the error message if the build is "failure".
	Err string `json:"err"`
}

// The "bucket" string in input is used for displaying and logging. It is not
// used to fetch anything from GCS.
func parseBuildsFromCache(bucketPrefixes []string, maxJobs int) ([]BuildResult, error) {
	// Let's only select the last few PRs.
	artifacts, err := findCachedArtifacts(bucketPrefixes, maxJobs)
	if err != nil {
		return nil, fmt.Errorf("failed to find cached artifacts: %v", err)
	}

	var results []BuildResult
	for _, artifact := range artifacts {
		if !strings.HasSuffix(artifact, "prowjob.json") {
			continue
		}

		bytes, err := loadFromCache(artifact)
		if err != nil {
			return nil, fmt.Errorf("failed to load from file %s, was expected to be already in cache: %w", artifact, err)
		}

		type prowJobV1 struct {
			Spec struct {
				Type      string `json:"type"`
				Agent     string `json:"agent"`
				Cluster   string `json:"cluster"`
				Namespace string `json:"namespace"`
				Job       string `json:"job"`
				Refs      struct {
					Org      string `json:"org"`
					Repo     string `json:"repo"`
					RepoLink string `json:"repo_link"`
					BaseRef  string `json:"base_ref"`
					BaseSha  string `json:"base_sha"`
					BaseLink string `json:"base_link"`
					Pulls    []struct {
						Number     int    `json:"number"`
						Author     string `json:"author"`
						Sha        string `json:"sha"`
						Title      string `json:"title"`
						Link       string `json:"link"`
						CommitLink string `json:"commit_link"`
						AuthorLink string `json:"author_link"`
					} `json:"pulls"`
				} `json:"refs"`
				Report         bool   `json:"report"`
				Context        string `json:"context"`
				RerunCommand   string `json:"rerun_command"`
				MaxConcurrency int    `json:"max_concurrency"`
				PodSpec        struct {
					Volumes []struct {
						Name     string `json:"name"`
						HostPath struct {
							Path string `json:"path"`
							Type string `json:"type"`
						} `json:"hostPath,omitempty"`
						Secret struct {
							SecretName string `json:"secretName"`
						} `json:"secret,omitempty"`
						EmptyDir struct {
						} `json:"emptyDir,omitempty"`
					} `json:"volumes"`
					Containers []struct {
						Name  string   `json:"name"`
						Image string   `json:"image"`
						Args  []string `json:"args"`
						Env   []struct {
							Name  string `json:"name"`
							Value string `json:"value"`
						} `json:"env"`
						Resources struct {
							Requests struct {
								CPU    string `json:"cpu"`
								Memory string `json:"memory"`
							} `json:"requests"`
						} `json:"resources"`
						VolumeMounts []struct {
							Name      string `json:"name"`
							ReadOnly  bool   `json:"readOnly,omitempty"`
							MountPath string `json:"mountPath"`
						} `json:"volumeMounts"`
						SecurityContext struct {
							Capabilities struct {
								Add []string `json:"add"`
							} `json:"capabilities"`
							Privileged bool `json:"privileged"`
						} `json:"securityContext"`
					} `json:"containers"`
					DNSConfig struct {
						Options []struct {
							Name  string `json:"name"`
							Value string `json:"value"`
						} `json:"options"`
					} `json:"dnsConfig"`
				} `json:"pod_spec"`
			} `json:"spec"`
			Status struct {
				StartTime      time.Time `json:"startTime"`
				PendingTime    time.Time `json:"pendingTime"`
				CompletionTime time.Time `json:"completionTime"`
				State          string    `json:"state"`
				Description    string    `json:"description"`
				URL            string    `json:"url"`
				PodName        string    `json:"pod_name"`
				BuildID        string    `json:"build_id"`
			} `json:"status"`
		}

		prowjob := prowJobV1{}
		err = json.Unmarshal(bytes, &prowjob)
		if err != nil {
			return nil, fmt.Errorf("failed to parse prowjob.json file %s: %w", artifact, err)
		}

		duration := int(math.Floor(prowjob.Status.CompletionTime.Sub(prowjob.Status.StartTime).Seconds()))
		var status BuildStatus
		switch prowjob.Status.State {
		case "success":
			status = BuildSuccess
		case "failure":
			status = BuildFailed
		case "pending", "aborted":
			// We don't care about pending builds. Aborted builds are not
			// interesting either since their duration won't make sense.
			continue
		default:
			return nil, fmt.Errorf("developer mistake: unknown state %s", prowjob.Status.State)
		}

		errStr := ""
		if prowjob.Status.State != "success" {
			errStr = prowjob.Status.Description
		}

		results = append(results, BuildResult{
			JobName:  prowjob.Spec.Job,
			Status:   status,
			Duration: duration,
			URL:      prowjob.Status.URL,
			Err:      errStr,
		})
	}

	return results, nil
}

func findCachedArtifacts(bucketPrefixes []string, maxJobs int) ([]string, error) {
	var prDirs []string
	for _, bucketPrefix := range bucketPrefixes {
		prDirEntries, err := os.ReadDir(cacheDir + "/" + bucketPrefix)
		if err != nil {
			return nil, fmt.Errorf("failed to read current directory: %v", err)
		}
		for _, dirEntry := range prDirEntries {
			if !dirEntry.IsDir() {
				continue
			}
			prDirs = append(prDirs, cacheDir+"/"+bucketPrefix+"/"+dirEntry.Name())
		}
	}

	prDirs, err := sortNumericDesc(prDirs)
	if err != nil {
		return nil, fmt.Errorf("failed to sort PR prefixes: %w", err)
	}

	countJobs := 0
	var artifacts []string
	for _, prDir := range prDirs {
		err := filepath.Walk(prDir, func(path string, _ os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if strings.HasSuffix(path, "prowjob.json") {
				countJobs++
			}

			artifacts = append(artifacts, path)

			if countJobs >= maxJobs {
				return io.EOF
			}

			return nil
		})
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("failed to recurse into %s: %w", prDir, err)
		}
		if countJobs >= maxJobs {
			break
		}
	}
	return artifacts, nil
}

type StatsMaxDuration struct {
	Name              string `json:"name"`
	MaxDurationPassed int    `json:"maxDurationPassed"` // in seconds
	MaxDurationFailed int    `json:"maxDurationFailed"`
}

func computeStatsMaxDuration(results []ginkgoResult) []StatsMaxDuration {
	type max struct {
		success int
		failed  int
	}

	// The key is the test name.
	maxMap := make(map[string]max)

	var testNames []string
	for _, test := range results {
		if _, ok := maxMap[test.Name]; !ok {
			testNames = append(testNames, test.Name)
			maxMap[test.Name] = max{success: 0, failed: 0}
		}
		cur := maxMap[test.Name]
		switch test.Status {
		case statusPassed:
			if cur.success < test.Duration {
				cur.success = test.Duration
			}
		case statusFailed:
			if cur.failed < test.Duration {
				cur.failed = test.Duration
			}
		}
		maxMap[test.Name] = cur
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
			Name:              name,
			MaxDurationPassed: maxMap[name].success,
			MaxDurationFailed: maxMap[name].failed,
		})
	}
	return stats
}

type StatsMostFailures struct {
	Name        string   `json:"name"`
	CountPassed int      `json:"countPassed"`
	CountFailed int      `json:"countFailed"`
	Errors      []string `json:"errors"`
}

// Sorted by ascending order of count of failures. Tests with no failures
// are skipped.
func computeStatsMostFailures(results []ginkgoResult) []StatsMostFailures {
	type count struct {
		passed int
		failed []string
	}

	// The key is the test name. The value is a list of failure messages.
	countMap := make(map[string]count)

	var testNames []string
	for _, test := range results {
		if test.Status != statusFailed && test.Status != statusPassed {
			continue
		}

		if _, ok := countMap[test.Name]; !ok {
			testNames = append(testNames, test.Name)
			countMap[test.Name] = count{}
		}

		cur := countMap[test.Name]
		switch test.Status {
		case statusPassed:
			cur.passed += 1
		case statusFailed:
			cur.failed = append(cur.failed, test.Err)
		}
		countMap[test.Name] = cur
	}

	sort.Slice(testNames, func(i, j int) bool {
		return len(countMap[testNames[i]].failed) < len(countMap[testNames[j]].failed)
	})

	var stats []StatsMostFailures
	for _, name := range testNames {
		if len(countMap[name].failed) == 0 {
			continue
		}

		stats = append(stats, StatsMostFailures{
			Name:        name,
			CountPassed: countMap[name].passed,
			CountFailed: len(countMap[name].failed),
			Errors:      countMap[name].failed,
		})
	}
	return stats
}

// The "skipped", "failed", and "error" tests are not taken into account. Only
// the and "passed" are dealt with. The "failed" and "error" results are to be
// fetched from build-log.txt files.
func parseJunit(bytes []byte) ([]parsedGinkgoBlock, error) {
	suites, err := junit.Ingest(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to ingest junit XML: %w", err)
	}

	var results []parsedGinkgoBlock
	for _, suite := range suites {
		for _, test := range suite.Tests {
			var s status
			switch test.Status {
			case "passed":
				s = statusPassed
			case "skipped", "failed", "error":
				continue
			}

			results = append(results, parsedGinkgoBlock{
				name: test.Name,
				// Anything lower than 1s should appear as "0s" since we don't
				// care about fast tests.
				duration: int(math.Floor(test.Duration.Seconds())),
				status:   s,
				errStr:   "",
				errLoc:   "",
			})
		}
	}
	return results, nil
}

// Returns the numerically ordered pull request prefixes in decreasing order.
// Prefixes that do not end with a number are skipped. The prefix string
// corresponds to the string that you would give to gsutil in order to list all
// the PRs; the ending "/" is optional:
//
//  gsutil ls gs://jetstack-logs/pr-logs/pull/jetstack_cert-manager
//                 <--bucket---> <----------- prefix ------------->
//
// The returned strings are ordered numerically by descreasing order and look
// like this:
//
//  pr-logs/pull/jetstack_cert-manager/20/
//  pr-logs/pull/jetstack_cert-manager/10/
//  pr-logs/pull/jetstack_cert-manager/2/
//  pr-logs/pull/jetstack_cert-manager/1/
//  <----------- prefix ------------->
func listPRPrefixes(bucket *storage.BucketHandle, prefixes []string) ([]string, error) {
	for i := range prefixes {
		if !strings.HasSuffix(prefixes[i], "/") {
			prefixes[i] += "/"
		}
	}

	var prPrefixes []string
	for _, prefix := range prefixes {
		prIter := bucket.Objects(context.Background(), &storage.Query{
			Prefix: prefix, Delimiter: "/", Projection: storage.ProjectionNoACL,
		})

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
	}

	prPrefixes, err := sortNumericDesc(prPrefixes)
	if err != nil {
		return nil, fmt.Errorf("failed to sort PR prefixes: %w", err)
	}

	return prPrefixes, nil
}

// Sorts using the numerical order by descreasing PR number. Ignores the ending
// "/" if there is one.
func sortNumericDesc(prPrefixes []string) ([]string, error) {
	// Sorting with strings.Compare would yield a lexicographical order of the
	// prPrefixes, it would look like this:
	//
	//  pr-logs/pull/jetstack_cert-manager/20/
	//  pr-logs/pull/jetstack_cert-manager/2/    <-- wrong
	//  pr-logs/pull/jetstack_cert-manager/10/
	//  pr-logs/pull/jetstack_cert-manager/1/
	//
	// Instead, we want a numerical ordering in descreasing order:
	//
	//  pr-logs/pull/jetstack_cert-manager/20/
	//  pr-logs/pull/jetstack_cert-manager/10/
	//  pr-logs/pull/jetstack_cert-manager/2/    <-- right
	//  pr-logs/pull/jetstack_cert-manager/1/
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

		return int1 >= int2
	})

	return prPrefixes, nil
}

// Get an object from the cache. No checksum is performed. It is assumed that
// downloadToCache was previously run. The name is expected to look like this:
//
//  pr-logs/pull/jetstack_cert-manager/1/build-log.txt
func loadFromCache(filePath string) ([]byte, error) {
	bytes, err := ioutil.ReadFile(filePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s does not exist in the cache: %v", filePath, err)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load a job artifact from cache: %s: %w", filePath, err)
	}
	return bytes, nil
}

// downloadToCache fetches the object from GCS and stores it in ~/.cache/prowdig/.
// If the object is already in the cache and its CRC32 sum matches the one in
// GCS, the cached object is returned. If the CRC32 sum does not match, the
// object is re-downloaded.
func downloadToCache(object *storage.ObjectAttrs, bucket *storage.BucketHandle) error {
	filePath := cacheDir + "/" + object.Name
	if _, err := os.Stat(filePath); err == nil {
		bytes, err := ioutil.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read from cache: %s: %w", object.Name, err)
		}

		if crc32.Checksum(bytes, crc32.MakeTable(crc32.Castagnoli)) == object.CRC32C {
			// We have hit the cache!
			return nil
		}

		fmt.Fprintf(os.Stderr, "warning: checksum for cache file %s does not match, it will be re-downloaded\n", filePath)
	}

	reader, err := bucket.Object(object.Name).NewReader(context.Background())
	if err != nil {
		return fmt.Errorf("failed to read GCS object: %s: %w", object.Name, err)
	}

	bytes, err := ioutil.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read GCS object: %s: %w", object.Name, err)
	}

	err = os.MkdirAll(path.Dir(filePath), 0755)
	if err != nil {
		return fmt.Errorf("failed to create cache dir: %w", err)
	}

	err = ioutil.WriteFile(filePath, bytes, 0644)
	if err != nil {
		return fmt.Errorf("failed to write to cache: %s: %w", object.Name, err)
	}

	return nil
}

//  pr-logs/pull/jetstack_cert-manager/4664/pull-cert-manager-e2e-v1-13/14356/artifacts/junit__01.xml
//                                     <--> <-------------------------> <--->
// 									 pr number        job name       build number
func parseObjectName(objectName string) (pr int, job string, build int, err error) {
	matches := reObjectName.FindStringSubmatch(objectName)
	if len(matches) != 4 {
		return 0, "", 0, fmt.Errorf("failed to parse object name, expected %s but got: %s", reObjectName.String(), os.Args[1])
	}

	pr, err = strconv.Atoi(matches[1])
	if err != nil {
		return 0, "", 0, fmt.Errorf("developer mistake: 1st capture in %s got: %s", reObjectName.String(), os.Args[1])
	}

	job = matches[2]

	build, err = strconv.Atoi(matches[3])
	if err != nil {
		return 0, "", 0, fmt.Errorf("developer mistake: 1st capture in %s got: %s", reObjectName.String(), os.Args[1])
	}

	return pr, job, build, nil
}
