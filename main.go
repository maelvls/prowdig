package main

import (
	"context"
	"flag"
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/joshdk/go-junit"
	"google.golang.org/api/iterator"
)

func green(s string) string {
	return fmt.Sprintf("\x1b[32m%s\x1b[0m", s)
}
func red(s string) string {
	return fmt.Sprintf("\x1b[31m%s\x1b[0m", s)
}

type status string

const (
	statusPassed status = "passed"
	statusFailed status = "failed"
)

type testcase struct {
	duration time.Duration
	status   status // "passed", "failed"
	name     string
	err      string
}

var rmAnsiColorsRe = regexp.MustCompile(`\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]`)

var reBuildLogFailures = regexp.MustCompile(`(?mi).*• FAILURE \[(?P<duration>\d+)\.\d+ .*
(?P<desc1>.*)\n.*\.go:\d+
(?:  (?P<desc2>.*)\n  .*\.go:\d+)?
(?:    (?P<desc3>.*)\n    .*\.go:\d+)?
?
 +Unexpected error:
(?:.*| .*\n)*
[^-] +(?P<err>.*)
 +occurred
?(?: .*| .*\n|\n)*
?
 +.*\.go:\d+
------------------------------
`)

func run() error {
	gcs, err := storage.NewClient(context.Background())
	if err != nil {
		return fmt.Errorf("failed to create GCS client: %v", err)
	}

	// The logs are in:
	// gs://jetstack-logs/pr-logs/pull/jetstack_cert-manager/4664/pull-cert-manager-e2e-v1-22/1471419639119482880
	bucket := gcs.Bucket("jetstack-logs")
	prsIter := bucket.Objects(context.Background(), &storage.Query{
		Prefix: "pr-logs/pull/jetstack_cert-manager/", Delimiter: "/", Projection: storage.ProjectionNoACL,
	})

	re := regexp.MustCompile(`/(\d+)/$`)
	var prPrefixes []string
	for {
		pr, err := prsIter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to iterate over GCS objects: %v", err)
		}

		// Some entries like "pr-logs/pull/jetstack_cert-manager/batch/..." do
		// not follow the PR convention. Let's skip them.
		if !re.MatchString(pr.Prefix) {
			continue
		}

		prPrefixes = append(prPrefixes, pr.Prefix)
	}

	// In order to have a numerical sorting (e.g, I want 400 to appear before
	// 3001), I extract the PR number from the end of the file prefix.
	sort.Slice(prPrefixes, func(i, j int) bool {
		matches := re.FindStringSubmatch(prPrefixes[i])
		if len(matches) != 2 {
			return true
		}

		int1, err := strconv.Atoi(matches[1])
		if err != nil {
			panic("developer mistake: " + err.Error())
		}

		matches = re.FindStringSubmatch(prPrefixes[j])
		if len(matches) != 2 {
			return false
		}

		int2, err := strconv.Atoi(matches[1])
		if err != nil {
			panic("developer mistake: " + err.Error())
		}

		return int1 < int2
	})

	if len(prPrefixes) > 20 {
		prPrefixes = prPrefixes[len(prPrefixes)-20:]
	}

	reIsJunit := regexp.MustCompile(`junit__.*\.xml$`)
	reIsBuildLogs := regexp.MustCompile(`build-log\.txt$`)

	var testcases []testcase
	for _, prPrefix := range prPrefixes {
		fileIter := bucket.Objects(context.Background(), &storage.Query{
			Prefix: prPrefix, Projection: storage.ProjectionNoACL,
		})

		fmt.Printf("fetching test artifacts under %s\n", prPrefix)
		for {
			file, err := fileIter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return fmt.Errorf("failed to iterate over GCS objects: %s: %w", file.Name, err)
			}

			if !reIsJunit.MatchString(file.Name) && !reIsBuildLogs.MatchString(file.Name) {
				continue
			}

			// Load from cache if it exists.
			var bytes []byte
			cachedFile := os.Getenv("HOME") + "/.cache/cmtestlenght/" + file.Name
			if _, err := os.Stat(cachedFile); err == nil {
				bytes, err = ioutil.ReadFile(os.Getenv("HOME") + "/.cache/cmtestlenght/" + file.Name)
				if err != nil {
					return fmt.Errorf("failed to read from cache: %s: %w", file.Name, err)
				}

				if crc32.Checksum(bytes, crc32.MakeTable(crc32.Castagnoli)) != file.CRC32C {
					return fmt.Errorf("cached file has invalid checksum, please remove %s", cachedFile)
				}
			} else {
				reader, err := bucket.Object(file.Name).NewReader(context.Background())
				if err != nil {
					return fmt.Errorf("failed to read GCS object: %s: %w", file.Name, err)
				}

				bytes, err = ioutil.ReadAll(reader)
				if err != nil {
					return fmt.Errorf("failed to read GCS object: %s: %w", file.Name, err)
				}

				err = os.MkdirAll(path.Dir(cachedFile), 0755)
				if err != nil {
					return fmt.Errorf("failed to create cache dir: %w", err)
				}

				err = ioutil.WriteFile(cachedFile, bytes, 0644)
				if err != nil {
					return fmt.Errorf("failed to write to cache: %s: %w", file.Name, err)
				}
			}

			switch {
			case reIsJunit.MatchString(file.Name):
				s, err := junit.Ingest(bytes)
				if err != nil {
					return fmt.Errorf("failed to ingest junit xml for file %s: %w", file.Name, err)
				}

				for _, suite := range s {
					for _, test := range suite.Tests {
						var s status
						switch test.Status {
						case "passed":
							s = statusPassed
						case "failed":
							s = statusFailed
						default:
							// We don't care about the "skipped" tests.
							continue
						}

						testcases = append(testcases, testcase{
							duration: test.Duration,
							status:   s,
							name:     test.Name,
						})
					}
				}

			case reIsBuildLogs.MatchString(file.Name):
				parsed, err := parseBuildLogs(bytes)
				if err != nil {
					return fmt.Errorf("failed to parse build logs for file %s: %w", file.Name, err)
				}
				testcases = append(testcases, parsed...)
			}
		}
	}

	type statistics struct {
		maxSuccess time.Duration
		maxFailed  time.Duration
	}

	testNames := []string{}
	statsMap := make(map[string]statistics)
	for _, testcase := range testcases {
		if _, ok := statsMap[testcase.name]; !ok {
			testNames = append(testNames, testcase.name)
			statsMap[testcase.name] = statistics{
				maxSuccess: 0,
				maxFailed:  0,
			}
		}
		cur := statsMap[testcase.name]
		switch testcase.status {
		case statusPassed:
			if cur.maxSuccess < testcase.duration {
				cur.maxSuccess = testcase.duration
			}
		case statusFailed:
			if cur.maxFailed < testcase.duration {
				cur.maxFailed = testcase.duration
			}
		}
		statsMap[testcase.name] = cur
	}

	// If there has been no failure, then we cannot say anything about the
	// timeout. So we filter out the tests that have no failure.
	var testNamesFiltered []string
	for _, name := range testNames {
		if statsMap[name].maxFailed == 0 {
			continue
		}
		testNamesFiltered = append(testNamesFiltered, name)
	}
	testNames = testNamesFiltered

	// We want to see the test cases for which the
	sort.Slice(testNames, func(i, j int) bool {
		return statsMap[testNames[i]].maxFailed-statsMap[testNames[i]].maxSuccess < statsMap[testNames[j]].maxFailed-statsMap[testNames[j]].maxSuccess
	})

	for _, name := range testNames {
		stats := statsMap[name]

		fmt.Printf("%s\t%s\t%s\n",
			green(stats.maxSuccess.Truncate(1*time.Second).String()),
			red(stats.maxFailed.Truncate(1*time.Second).String()),
			name,
		)
	}

	return nil
}

// Also removes the "[It]" suffixes from the test names.
func parseBuildLogs(bytes []byte) ([]testcase, error) {
	str := string(bytes)
	str = rmAnsiColorsRe.ReplaceAllString(str, "")
	matches := FindAllStringSubmatchMap(reBuildLogFailures, str)

	var testcases []testcase
	for _, match := range matches {
		duration := match["duration"]
		seconds, err := strconv.Atoi(duration)
		if err != nil {
			return nil, fmt.Errorf("duration '%s' is not an integer", duration)
		}
		desc := strings.TrimSuffix(match["desc1"], " [It]")
		if match["desc2"] != "" {
			desc += " " + strings.TrimSuffix(match["desc2"], " [It]")
		}
		if match["desc3"] != "" {
			desc += " " + strings.TrimSuffix(match["desc3"], " [It]")
		}

		testcases = append(testcases, testcase{
			duration: time.Duration(seconds) * time.Second,
			name:     desc,
			status:   statusFailed,
			err:      match["err"],
		})
	}
	return testcases, nil
}

func main() {
	flag.Parse()
	err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// I want a list of matches, and each match is a map of the named submatches.
func FindAllStringSubmatchMap(r *regexp.Regexp, str string) []map[string]string {
	var submatchMaps []map[string]string
	matches := r.FindAllStringSubmatch(str, -1)
	for _, match := range matches {
		submatchMap := make(map[string]string)
		for i, name := range r.SubexpNames() {
			if i != 0 {
				submatchMap[name] = match[i]
			}
		}
		submatchMaps = append(submatchMaps, submatchMap)
	}

	return submatchMaps
}
