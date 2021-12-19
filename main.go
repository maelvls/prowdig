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

type status string

const (
	statusPassed status = "passed"
	statusFailed status = "failed"
)

// Watch out, one test case outcome may appear twice in the array of testcases.
// We do not do de-duplication yet.
type testcase struct {
	duration time.Duration
	status   status
	name     string
	err      string
}

var (
	rmAnsiColorsRe     = regexp.MustCompile(`\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]`)
	reBuildLogFailures = regexp.MustCompile(`(?mi).*• FAILURE \[(?P<duration>\d+)\.\d+ .*
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
)

func main() {
	flag.Parse()
	err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

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

	isJunit := regexp.MustCompile(`junit__.*\.xml$`)
	isBuildLogs := regexp.MustCompile(`build-log\.txt$`)

	// Beware the duplicates!! One test case for a given job may appear in both
	// a junit file and in the build-log.txt. We do not de-duplicate them at the
	// moment.
	var testcases []testcase
	for _, prPrefix := range prPrefixes {
		fileIter := bucket.Objects(context.Background(), &storage.Query{
			Prefix: prPrefix, Projection: storage.ProjectionNoACL,
		})

		// For each PR prefix such as pr-logs/pull/jetstack_cert-manager/4664/,
		// we fetch all the junit files and build-log.txt files. For example, these are going to be the ""
		// want the following to be included:
		//
		//   pr-logs/pull/jetstack_cert-manager/1016/pull-cert-manager-e2e-v1-13/231/build-log.txt
		//   pr-logs/pull/jetstack_cert-manager/1016/pull-cert-manager-e2e-v1-13/231/artifacts/junit__01.xml
		//   pr-logs/pull/jetstack_cert-manager/1016/pull-cert-manager-e2e-v1-13/231/artifacts/junit__02.xml
		//   pr-logs/pull/jetstack_cert-manager/1016/pull-cert-manager-e2e-v1-13/231/artifacts/junit__03.xml
		//   pr-logs/pull/jetstack_cert-manager/1016/pull-cert-manager-e2e-v1-13/231/artifacts/junit__10.xml
		//   <----------- prPrefix ------------>
		//   <----------- file ---------------------------------------------------------------------------->
		fmt.Fprintf(os.Stderr, "fetching test artifacts under %s\n", prPrefix)
		for {
			file, err := fileIter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return fmt.Errorf("failed to iterate over GCS objects: %s: %w", file.Name, err)
			}

			if !isJunit.MatchString(file.Name) && !isBuildLogs.MatchString(file.Name) {
				continue
			}

			bytes, err := fetchObjectCached(file, bucket)
			if err != nil {
				return fmt.Errorf("failed to fetch %s: %w", file.Name, err)
			}

			switch {
			case isJunit.MatchString(file.Name):
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

			case isBuildLogs.MatchString(file.Name):
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

// fetchObjectCached fetches the object from GCS and stores it in
// ~/.cache/prowdig/. If the object is already in the cache and its CRC32 sum
// matches the one in GCS, the cached object is returned. If the CRC32 sum does
// not match, the object is re-downloaded.
func fetchObjectCached(file *storage.ObjectAttrs, bucket *storage.BucketHandle) ([]byte, error) {
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

// Also removes the "[It]" suffixes from the test names. This function expects
// the content of the build-log.txt file, and expects Ginkgo-style errors of the
// form:
//
//   • Failure [301.437 seconds]                            <- duration ("301")
//   [Conformance] Certificates                             <- desc1
//   test/e2e/framework/framework.go:287
//     with issuer type External ClusterIssuer              <- desc2 (optional)
//     test/e2e/suite/conformance/certificates.go:47
//       should issue a cert with wildcard DNS Name [It]    <- desc3 (optional)
//       test/e2e/suite/conformance/certificates.go:105
//       Unexpected error:
//
//           <*errors.errorString | 0xc0001c07b0>: {
//               s: "timed out waiting for the condition",
//           }
//           timed out waiting for the condition           <- err
//       occurred
//       test/e2e/suite/conformance/certificates.go:522
//   ------------------------------
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

func green(s string) string {
	return fmt.Sprintf("\x1b[32m%s\x1b[0m", s)
}
func red(s string) string {
	return fmt.Sprintf("\x1b[31m%s\x1b[0m", s)
}
