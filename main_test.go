package main

import (
	"embed"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed test/*.txt
var fs embed.FS

func Test_CLI_tests_parse_logs(t *testing.T) {
	// We want to fake the behavior of the URL
	// https://storage.googleapis.com/jetstack-logs/logs/ci-cert-manager-master-e2e-v1-21/1561754583443705856/build-log.txt
	// so that we can test the behavior of "prowdig tests parse-logs https://storage.googleapis.com/...".

	serve := func(w http.ResponseWriter, r *http.Request) {
		t.Log(r.URL.Path, r.Method, r.Host)
		if r.URL.Path != "/jetstack-logs/logs/ci-cert-manager-master-e2e-v1-21/1561754583443705856/build-log.txt" || r.Method != "GET" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		f, err := fs.Open("test/build-log.txt")
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(err.Error()))
			return
		}
		defer f.Close()

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, err = io.Copy(w, f)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	server := httptest.NewServer(http.HandlerFunc(serve))
	defer server.Close()

	bincli := withBinary(t)
	cli := startWith(t, exec.Command(bincli, "tests", "parse-logs", server.URL+"/jetstack-logs/logs/ci-cert-manager-master-e2e-v1-21/1561754583443705856/build-log.txt")).Wait()
	assert.Equal(t, 0, cli.ProcessState.ExitCode())

	assert.Equal(t, `❌ 55s [Conformance] CertificateSigningRequests CertificateSigningRequest with issuer type Vault AppRole ClusterIssuer With Root CA should issue an RSA certificate for a single Common Name: failed to create vault issuer
Internal error occurred: failed calling webhook "webhook.cert-manager.io": failed to call webhook: Post "https://cert-manager-webhook.cert-manager.svc:443/mutate?timeout=10s": dial tcp 10.96.139.176:443: connect: connection refused
❌ 1m2s [Conformance] CertificateSigningRequests CertificateSigningRequest with issuer type Vault AppRole Issuer With Root CA should issue a certificate that includes only a URISANs name: failed to create vault issuer
Internal error occurred: failed calling webhook "webhook.cert-manager.io": failed to call webhook: Post "https://cert-manager-webhook.cert-manager.svc:443/validate?timeout=10s": context deadline exceeded
❌ 37s [Conformance] CertificateSigningRequests CertificateSigningRequest with issuer type Vault AppRole Issuer With Root CA should issue a certificate that includes only a URISANs name: failed to create vault issuer
Internal error occurred: failed calling webhook "webhook.cert-manager.io": failed to call webhook: Post "https://cert-manager-webhook.cert-manager.svc:443/mutate?timeout=10s": dial tcp 10.96.139.176:443: connect: connection refused
❌ 1s [Conformance] Certificates with issuer type ACME DNS01 Issuer should issue a certificate for a single distinct DNS Name defined by an ingress with annotations: failed to create acme DNS01 Issuer
Internal error occurred: failed calling webhook "webhook.cert-manager.io": failed to call webhook: Post "https://cert-manager-webhook.cert-manager.svc:443/mutate?timeout=10s": dial tcp 10.96.139.176:443: connect: connection refused
❌ 8s  [cert-manager] Certificate SecretTemplate should add Annotations and Labels to the Secret when the Certificate's SecretTemplate is updated, then remove Annotations and Labels when removed from the SecretTemplate: Operation cannot be fulfilled on certificates.cert-manager.io "test-secret-template-zpbwh": the object has been modified; please apply your changes to the latest version and try again
❌ 7s  [cert-manager] Certificate SecretTemplate should add Annotations and Labels to the Secret when the Certificate's SecretTemplate is updated, then remove Annotations and Labels when removed from the SecretTemplate: Operation cannot be fulfilled on certificates.cert-manager.io "test-secret-template-cd7cx": the object has been modified; please apply your changes to the latest version and try again
❌ 34s [cert-manager] Certificate SecretTemplate should not remove Annotations and Labels which have been added by a third party and not present in the SecretTemplate: failed to wait for Certificate to become Ready
timed out waiting for the condition
❌ 37s [cert-manager] Certificate SecretTemplate should not remove Annotations and Labels which have been added by a third party and not present in the SecretTemplate: failed to wait for Certificate to become Ready
timed out waiting for the condition
❌ 42s [cert-manager] Vault Issuer Certificate (AppRole, CA with root) should generate a new certificate with a warning event when renewBefore is bigger than the duration: Internal error occurred: failed calling webhook "webhook.cert-manager.io": failed to call webhook: Post "https://cert-manager-webhook.cert-manager.svc:443/mutate?timeout=10s": dial tcp 10.96.139.176:443: connect: connection refused
`, contents(cli.Output))
}

func Test_reGinkgoBlock(t *testing.T) {
	block, err := parseGinkgoBlock(ginkgoBlock{line: 42, lines: strings.Split(exampleGingkoBlock1, "\n")})
	assert.NoError(t, err)
	assert.Equal(t, parsedGinkgoBlock{
		name:     "[cert-manager] Approval CertificateRequests a service account with the approve permissions for cluster scoped issuers.example.io/* should be able to deny requests",
		status:   "failed",
		duration: 0,
		errStr:   "admission webhook \"webhook.cert-manager.io\" denied the request: spec.issuerRef: Forbidden: referenced signer resource does not exist: {test-issuer Issuer bycbn.example.io}",
		errLoc:   "test/e2e/suite/approval/approval.go:233",
	}, block)

	block, err = parseGinkgoBlock(ginkgoBlock{line: 123, lines: strings.Split(exampleGingkoBlock2, "\n")})
	assert.NoError(t, err)
	assert.Equal(t, parsedGinkgoBlock{
		name:     "[Conformance] Certificates with issuer type SelfSigned ClusterIssuer should issue an ECDSA, defaulted certificate for a single distinct DNS Name",
		status:   "failed",
		duration: 301,
		errStr:   "timed out waiting for the condition",
		errLoc:   "test/e2e/suite/conformance/certificates/tests.go:149",
		// Source:   "/file/build-log.txt:123",
	}, block)

	block, err = parseGinkgoBlock(ginkgoBlock{line: 456, lines: strings.Split(exampleGingkoBlock3, "\n")})
	assert.NoError(t, err)
	assert.Equal(t, parsedGinkgoBlock{
		name:     "[cert-manager] Certificate SecretTemplate should update the values of keys that have been modified in the SecretTemplate",
		status:   "failed",
		duration: 6,
		errStr:   "Timed out after 5.000s.\nExpected\n    <map[string]string | len:10>: {\n        \"foo\": \"bar\",\n        \"bar\": \"foo\",\n        \"cert-manager.io/ip-sans\": \"\",\n        \"cert-manager.io/issuer-group\": \"cert-manager.io\",\n        \"cert-manager.io/issuer-kind\": \"Issuer\",\n        \"cert-manager.io/issuer-name\": \"certificate-secret-template\",\n        \"cert-manager.io/uri-sans\": \"\",\n        \"cert-manager.io/alt-names\": \"\",\n        \"cert-manager.io/certificate-name\": \"test-secret-template-qbwsc\",\n        \"cert-manager.io/common-name\": \"test\",\n    }\nto have {key: value}\n    <map[interface {}]interface {} | len:1>: {\n        <string>\"foo\": <string>\"123\",\n    }",
		errLoc:   "test/e2e/suite/secrettemplate/secrettemplate.go:202",
	}, block)

	block, err = parseGinkgoBlock(ginkgoBlock{line: 789, lines: strings.Split(exampleGingkoBlock4, "\n")})
	assert.NoError(t, err)
	assert.Equal(t, parsedGinkgoBlock{
		name:     "[cert-manager] ACME CertificateRequest (HTTP01) should automatically recreate challenge pod and still obtain a certificate if it is manually deleted [BeforeEach]",
		status:   "error",
		duration: 61,
		errStr:   "timed out waiting for the condition",
		errLoc:   "test/e2e/suite/issuers/acme/certificaterequest/http01.go:93",
	}, block)
}

func Test_parseBuildLog(t *testing.T) {
	blocks, err := parseBuildLog([]byte(exampleBuildLog))
	assert.NoError(t, err)
	assert.Len(t, blocks, 6)

	assert.Equal(t, 18, blocks[0].line)
	assert.Equal(t, []string{
		"• Failure [301.574 seconds]",
		"[Conformance] Certificates",
		"test/e2e/framework/framework.go:287",
		"  with issuer type SelfSigned ClusterIssuer",
		"  test/e2e/suite/conformance/certificates/tests.go:47",
		"    should issue an ECDSA, defaulted certificate for a single distinct DNS Name [It]",
		"    test/e2e/suite/conformance/certificates/suite.go:105",
		"",
		"    Unexpected error:",
		"        <*errors.errorString | 0xc0001c07d0>: {",
		"            s: \"timed out waiting for the condition\",",
		"        }",
		"        timed out waiting for the condition",
		"    occurred",
		"",
		"    test/e2e/suite/conformance/certificates/tests.go:149",
		"------------------------------",
	}, blocks[0].lines)

	assert.Equal(t, 47, blocks[1].line)
	assert.Equal(t, []string{
		"• Failure [0.510 seconds]",
		"[cert-manager] Approval CertificateRequests",
		"test/e2e/framework/framework.go:283",
		"  a service account with the approve permissions for cluster scoped issuers.example.io/* should be able to deny requests [It]",
		"  test/e2e/suite/approval/approval.go:225",
		"",
		"  Unexpected error:",
		"      <*errors.StatusError | 0xc0015c0a00>: {",
		"          ErrStatus: {",
		"              TypeMeta: {Kind: \"\", APIVersion: \"\"},",
		"              ListMeta: {",
		"                  SelfLink: \"\",",
		"                  ResourceVersion: \"\",",
		"                  Continue: \"\",",
		"                  RemainingItemCount: nil,",
		"              },",
		"              Status: \"Failure\",",
		"              Message: \"admission webhook \\\"webhook.cert-manager.io\\\" denied the request: spec.issuerRef: Forbidden: referenced signer resource does not exist",
		": {test-issuer Issuer bycbn.example.io}\",",
		"              Reason: \"NotAcceptable\",",
		"              Details: nil,",
		"              Code: 406,",
		"          },",
		"      }",
		"      admission webhook \"webhook.cert-manager.io\" denied the request: spec.issuerRef: Forbidden: referenced signer resource does not exist: {test-issuer Issuer bycbn.example.io}",
		"  occurred",
		"",
		"  test/e2e/suite/approval/approval.go:233",
		"------------------------------",
	}, blocks[1].lines)

	assert.Equal(t, 67, blocks[2].line)
	assert.Equal(t, []string{
		"• Failure [309.036 seconds]",
		"[cert-manager] Vault ClusterIssuer CertificateRequest (AppRole)",
		"test/e2e/framework/framework.go:283",
		"  should generate a new certificate with Vault configured maximum TTL duration (90 days) when requested duration is greater than TTL [It]",
		"  test/e2e/suite/issuers/vault/certificaterequest/approle.go:215",
		"",
		"  Unexpected error:",
		"      <*errors.errorString | 0xc00024a7a0>: {",
		"          s: \"timed out waiting for the condition\",",
		"      }",
		"      timed out waiting for the condition",
		"  occurred",
		"",
		"  test/e2e/suite/issuers/vault/certificaterequest/approle.go:270",
		"------------------------------",
	}, blocks[2].lines)

	assert.Equal(t, 102, blocks[3].line)
	assert.Equal(t, []string{
		"• Failure [6.603 seconds]",
		"[cert-manager] Certificate SecretTemplate",
		"test/e2e/framework/framework.go:283",
		"  should update the values of keys that have been modified in the SecretTemplate [It]",
		"  test/e2e/suite/secrettemplate/secrettemplate.go:173",
		"",
		"  Timed out after 5.000s.",
		"  Expected",
		"      <map[string]string | len:10>: {",
		"          \"foo\": \"bar\",",
		"          \"bar\": \"foo\",",
		"          \"cert-manager.io/ip-sans\": \"\",",
		"          \"cert-manager.io/issuer-group\": \"cert-manager.io\",",
		"          \"cert-manager.io/issuer-kind\": \"Issuer\",",
		"          \"cert-manager.io/issuer-name\": \"certificate-secret-template\",",
		"          \"cert-manager.io/uri-sans\": \"\",",
		"          \"cert-manager.io/alt-names\": \"\",",
		"          \"cert-manager.io/certificate-name\": \"test-secret-template-qbwsc\",",
		"          \"cert-manager.io/common-name\": \"test\",",
		"      }",
		"  to have {key: value}",
		"      <map[interface {}]interface {} | len:1>: {",
		"          <string>\"foo\": <string>\"123\",",
		"      }",
		"",
		"  test/e2e/suite/secrettemplate/secrettemplate.go:202",
		"------------------------------",
	}, blocks[3].lines)

	assert.Equal(t, 122, blocks[4].line)
	assert.Equal(t, []string{
		"• Failure [71.567 seconds]",
		"[cert-manager] Vault Issuer",
		"test/e2e/framework/framework.go:266",
		"  should be ready with a valid Kubernetes Role and ServiceAccount Secret [It]",
		"  test/e2e/suite/issuers/vault/issuer.go:180",
		"",
		"  Unexpected error:",
		"      <*errors.errorString | 0xc000d55bb0>: {",
		"          s: \"timed out waiting for the condition: Last Status: 'False' Reason: 'VaultError', Message: 'Failed to initialize Vault client: error reading Kubernetes service account token from vault-serviceaccount: error calling Vault server: Error making API request.\\n\\nURL: POST https://vault.e2e-tests-create-vault-issuer-klmxs:8200/v1/auth/kubernetes/login\\nCode: 403. Errors:\\n\\n* permission denied'\",",
		"      }",
		"      timed out waiting for the condition: Last Status: 'False' Reason: 'VaultError', Message: 'Failed to initialize Vault client: error reading Kubernetes service account token from vault-serviceaccount: error calling Vault server: Error making API request.",
		"      ",
		"      URL: POST https://vault.e2e-tests-create-vault-issuer-klmxs:8200/v1/auth/kubernetes/login",
		"      Code: 403. Errors:",
		"      ",
		"      * permission denied'",
		"  occurred",
		"",
		"  test/e2e/suite/issuers/vault/issuer.go:200",
		"------------------------------",
	}, blocks[4].lines)

	assert.Equal(t, 137, blocks[5].line)
	assert.Equal(t, []string{
		"• Failure in Spec Setup (BeforeEach) [61.637 seconds]",
		"[cert-manager] ACME CertificateRequest (HTTP01)",
		"test/e2e/framework/framework.go:283",
		"  should automatically recreate challenge pod and still obtain a certificate if it is manually deleted [BeforeEach]",
		"  test/e2e/suite/issuers/acme/certificaterequest/http01.go:207",
		"",
		"  Unexpected error:",
		"      <*errors.errorString | 0xc000234850>: {",
		"          s: \"timed out waiting for the condition\",",
		"      }",
		"      timed out waiting for the condition",
		"  occurred",
		"",
		"  test/e2e/suite/issuers/acme/certificaterequest/http01.go:93",
		"------------------------------",
	}, blocks[5].lines)
}

const exampleBuildLog = `
• Failure [301.574 seconds]
[Conformance] Certificates
test/e2e/framework/framework.go:287
  with issuer type SelfSigned ClusterIssuer
  test/e2e/suite/conformance/certificates/tests.go:47
    should issue an ECDSA, defaulted certificate for a single distinct DNS Name [It]
    test/e2e/suite/conformance/certificates/suite.go:105

    Unexpected error:
        <*errors.errorString | 0xc0001c07d0>: {
            s: "timed out waiting for the condition",
        }
        timed out waiting for the condition
    occurred

    test/e2e/suite/conformance/certificates/tests.go:149
------------------------------
• Failure [0.510 seconds]
[cert-manager] Approval CertificateRequests
test/e2e/framework/framework.go:283
  a service account with the approve permissions for cluster scoped issuers.example.io/* should be able to deny requests [It]
  test/e2e/suite/approval/approval.go:225

  Unexpected error:
      <*errors.StatusError | 0xc0015c0a00>: {
          ErrStatus: {
              TypeMeta: {Kind: "", APIVersion: ""},
              ListMeta: {
                  SelfLink: "",
                  ResourceVersion: "",
                  Continue: "",
                  RemainingItemCount: nil,
              },
              Status: "Failure",
              Message: "admission webhook \"webhook.cert-manager.io\" denied the request: spec.issuerRef: Forbidden: referenced signer resource does not exist
: {test-issuer Issuer bycbn.example.io}",
              Reason: "NotAcceptable",
              Details: nil,
              Code: 406,
          },
      }
      admission webhook "webhook.cert-manager.io" denied the request: spec.issuerRef: Forbidden: referenced signer resource does not exist: {test-issuer Issuer bycbn.example.io}
  occurred

  test/e2e/suite/approval/approval.go:233
------------------------------

#
# Example with ANSI color codes
#

• Failure [309.036 seconds]
[cert-manager] Vault ClusterIssuer CertificateRequest (AppRole)
test/e2e/framework/framework.go:283
  should generate a new certificate with Vault configured maximum TTL duration (90 days) when requested duration is greater than TTL [It]
  test/e2e/suite/issuers/vault/certificaterequest/approle.go:215

  Unexpected error:
      <*errors.errorString | 0xc00024a7a0>: {
          s: "timed out waiting for the condition",
      }
      timed out waiting for the condition
  occurred

  test/e2e/suite/issuers/vault/certificaterequest/approle.go:270
------------------------------
• [SLOW TEST:25.601 seconds]
[Conformance] Certificates
test/e2e/framework/framework.go:287
  with issuer type ACME HTTP01 Issuer (Ingress)
  test/e2e/suite/conformance/certificates/tests.go:47
    should issue a certificate for a single distinct DNS Name defined by an ingress with annotations
    test/e2e/suite/conformance/certificates/suite.go:105
------------------------------
• Failure [6.603 seconds]
[cert-manager] Certificate SecretTemplate
test/e2e/framework/framework.go:283
  should update the values of keys that have been modified in the SecretTemplate [It]
  test/e2e/suite/secrettemplate/secrettemplate.go:173

  Timed out after 5.000s.
  Expected
      <map[string]string | len:10>: {
          "foo": "bar",
          "bar": "foo",
          "cert-manager.io/ip-sans": "",
          "cert-manager.io/issuer-group": "cert-manager.io",
          "cert-manager.io/issuer-kind": "Issuer",
          "cert-manager.io/issuer-name": "certificate-secret-template",
          "cert-manager.io/uri-sans": "",
          "cert-manager.io/alt-names": "",
          "cert-manager.io/certificate-name": "test-secret-template-qbwsc",
          "cert-manager.io/common-name": "test",
      }
  to have {key: value}
      <map[interface {}]interface {} | len:1>: {
          <string>"foo": <string>"123",
      }

  test/e2e/suite/secrettemplate/secrettemplate.go:202
------------------------------
• Failure [71.567 seconds]
[cert-manager] Vault Issuer
test/e2e/framework/framework.go:266
  should be ready with a valid Kubernetes Role and ServiceAccount Secret [It]
  test/e2e/suite/issuers/vault/issuer.go:180

  Unexpected error:
      <*errors.errorString | 0xc000d55bb0>: {
          s: "timed out waiting for the condition: Last Status: 'False' Reason: 'VaultError', Message: 'Failed to initialize Vault client: error reading Kubernetes service account token from vault-serviceaccount: error calling Vault server: Error making API request.\n\nURL: POST https://vault.e2e-tests-create-vault-issuer-klmxs:8200/v1/auth/kubernetes/login\nCode: 403. Errors:\n\n* permission denied'",
      }
      timed out waiting for the condition: Last Status: 'False' Reason: 'VaultError', Message: 'Failed to initialize Vault client: error reading Kubernetes service account token from vault-serviceaccount: error calling Vault server: Error making API request.
      
      URL: POST https://vault.e2e-tests-create-vault-issuer-klmxs:8200/v1/auth/kubernetes/login
      Code: 403. Errors:
      
      * permission denied'
  occurred

  test/e2e/suite/issuers/vault/issuer.go:200
------------------------------
• Failure in Spec Setup (BeforeEach) [61.637 seconds]
[cert-manager] ACME CertificateRequest (HTTP01)
test/e2e/framework/framework.go:283
  should automatically recreate challenge pod and still obtain a certificate if it is manually deleted [BeforeEach]
  test/e2e/suite/issuers/acme/certificaterequest/http01.go:207

  Unexpected error:
      <*errors.errorString | 0xc000234850>: {
          s: "timed out waiting for the condition",
      }
      timed out waiting for the condition
  occurred

  test/e2e/suite/issuers/acme/certificaterequest/http01.go:93
------------------------------
`

var exampleGingkoBlock1 = `• Failure [0.510 seconds]
[cert-manager] Approval CertificateRequests
test/e2e/framework/framework.go:283
  a service account with the approve permissions for cluster scoped issuers.example.io/* should be able to deny requests [It]
  test/e2e/suite/approval/approval.go:225

  Unexpected error:
      <*errors.StatusError | 0xc0015c0a00>: {
          ErrStatus: {
              TypeMeta: {Kind: "", APIVersion: ""},
              ListMeta: {
                  SelfLink: "",
                  ResourceVersion: "",
                  Continue: "",
                  RemainingItemCount: nil,
              },
              Status: "Failure",
              Message: "admission webhook \"webhook.cert-manager.io\" denied the request: spec.issuerRef: Forbidden: referenced signer resource does not exist: {test-issuer Issuer bycbn.example.io}",
              Reason: "NotAcceptable",
              Details: nil,
              Code: 406,
          },
      }
      admission webhook "webhook.cert-manager.io" denied the request: spec.issuerRef: Forbidden: referenced signer resource does not exist: {test-issuer Issuer bycbn.example.io}
  occurred

  test/e2e/suite/approval/approval.go:233
------------------------------`

var exampleGingkoBlock2 = `• Failure [301.574 seconds]
[Conformance] Certificates
test/e2e/framework/framework.go:287
  with issuer type SelfSigned ClusterIssuer
  test/e2e/suite/conformance/certificates/tests.go:47
    should issue an ECDSA, defaulted certificate for a single distinct DNS Name [It]
    test/e2e/suite/conformance/certificates/suite.go:105

    Unexpected error:
        <*errors.errorString | 0xc0001c07d0>: {
            s: "timed out waiting for the condition",
        }
        timed out waiting for the condition
    occurred

    test/e2e/suite/conformance/certificates/tests.go:149
------------------------------`

var exampleGingkoBlock3 = `• Failure [6.603 seconds]
[cert-manager] Certificate SecretTemplate
test/e2e/framework/framework.go:283
  should update the values of keys that have been modified in the SecretTemplate [It]
  test/e2e/suite/secrettemplate/secrettemplate.go:173

  Timed out after 5.000s.
  Expected
      <map[string]string | len:10>: {
          "foo": "bar",
          "bar": "foo",
          "cert-manager.io/ip-sans": "",
          "cert-manager.io/issuer-group": "cert-manager.io",
          "cert-manager.io/issuer-kind": "Issuer",
          "cert-manager.io/issuer-name": "certificate-secret-template",
          "cert-manager.io/uri-sans": "",
          "cert-manager.io/alt-names": "",
          "cert-manager.io/certificate-name": "test-secret-template-qbwsc",
          "cert-manager.io/common-name": "test",
      }
  to have {key: value}
      <map[interface {}]interface {} | len:1>: {
          <string>"foo": <string>"123",
      }

  test/e2e/suite/secrettemplate/secrettemplate.go:202
------------------------------`

var exampleGingkoBlock4 = `• Failure in Spec Setup (BeforeEach) [61.637 seconds]
[cert-manager] ACME CertificateRequest (HTTP01)
test/e2e/framework/framework.go:283
  should automatically recreate challenge pod and still obtain a certificate if it is manually deleted [BeforeEach]
  test/e2e/suite/issuers/acme/certificaterequest/http01.go:207

  Unexpected error:
      <*errors.errorString | 0xc000234850>: {
          s: "timed out waiting for the condition",
      }
      timed out waiting for the condition
  occurred

  test/e2e/suite/issuers/acme/certificaterequest/http01.go:93
------------------------------`

// Tests that have been retried e.g. with FLAKE_ATTEMPTS=2 should not count
// twice in the total number of tests.
var exampleGingkoBlock5 = `
STEP: Deleting test namespace

• Failure [300.969 seconds]
[Conformance] Certificates with External Account Binding
test/e2e/framework/framework.go:287
  with issuer type ACME HTTP01 Issuer (Gateway)
  test/e2e/suite/conformance/certificates/tests.go:47
    Creating a Gateway with annotations for issuerRef and other Certificate fields [It]
    test/e2e/suite/conformance/certificates/suite.go:105

    Unexpected error:
        <*errors.errorString | 0xc000242850>: {
            s: "timed out waiting for the condition",
        }
        timed out waiting for the condition
    occurred

    test/e2e/suite/conformance/certificates/tests.go:819
------------------------------

• Failure [300.851 seconds]
[Conformance] Certificates
test/e2e/framework/framework.go:287
  with issuer type ACME HTTP01 Issuer (Ingress)
  test/e2e/suite/conformance/certificates/tests.go:47
    Creating a Gateway with annotations for issuerRef and other Certificate fields [It]
    test/e2e/suite/conformance/certificates/suite.go:105

    Unexpected error:
        <*errors.errorString | 0xc0001c2850>: {
            s: "timed out waiting for the condition",
        }
        timed out waiting for the condition
    occurred

    test/e2e/suite/conformance/certificates/tests.go:819
------------------------------
[BeforeEach] CertificateSigningRequest with issuer type Vault AppRole Custom Auth Path ClusterIssuer With Root CA
  test/e2e/framework/framework.go:111
STEP: Creating a kubernetes client
STEP: Creating an API extensions client
STEP: Creating a cert manager client
STEP: Creating a controller-runtime client
STEP: Creating a gateway-api client
STEP: Building a namespace api object
STEP: Using the namespace e2e-tests-certificatesigningrequests-r585z
STEP: Building a ResourceQuota api object
[BeforeEach] CertificateSigningRequest with issuer type Vault AppRole Custom Auth Path ClusterIssuer With Root CA
  test/e2e/suite/conformance/certificatesigningrequests/tests.go:65
[It] should issue a certificate that defines a Common Name, DNS Name, and sets a duration
  test/e2e/suite/conformance/certificatesigningrequests/suite.go:109
STEP: Creating an issuer resource
STEP: Creating a VaultAppRole ClusterIssuer
NAME: chart-vault-cm-e2e-create-vault-issuer
LAST DEPLOYED: Wed Jul  6 13:12:42 2022
NAMESPACE: e2e-tests-certificatesigningrequests-r585z
STATUS: deployed
REVISION: 1
TEST SUITE: None
STEP: Waiting 2m0s for all pods in namespace 'e2e-tests-certificatesigningrequests-r585z' to be Ready
Jul  6 13:13:15.824: INFO:  (took 0s)
STEP: Configuring the VaultAppRole server
[AfterEach] CertificateSigningRequest with issuer type Vault AppRole Custom Auth Path ClusterIssuer With Root CA
  test/e2e/framework/framework.go:112
STEP: Deleting test namespace


• Failure [46.524 seconds]
[Conformance] CertificateSigningRequests
test/e2e/framework/framework.go:276
  CertificateSigningRequest with issuer type Vault AppRole Custom Auth Path ClusterIssuer With Root CA
  test/e2e/suite/conformance/certificatesigningrequests/tests.go:51
    should issue a certificate that defines a Common Name, DNS Name, and sets a duration [It]
    test/e2e/suite/conformance/certificatesigningrequests/suite.go:109

    failed to create vault issuer
    Unexpected error:
        <*errors.StatusError | 0xc00167a000>: {
            ErrStatus: {
                TypeMeta: {Kind: "", APIVersion: ""},
                ListMeta: {
                    SelfLink: "",
                    ResourceVersion: "",
                    Continue: "",
                    RemainingItemCount: nil,
                },
                Status: "Failure",
                Message: "Internal error occurred: failed calling webhook \"webhook.cert-manager.io\": failed to call webhook: Post \"https://cert-manager-webhook.cert-manager.svc:443/mutate?timeout=10s\": dial tcp 10.96.191.224:443: connect: connection refused",
                Reason: "InternalError",
                Details: {
                    Name: "",
                    Group: "",
                    Kind: "",
                    UID: "",
                    Causes: [
                        {
                            Type: "",
                            Message: "failed calling webhook \"webhook.cert-manager.io\": failed to call webhook: Post \"https://cert-manager-webhook.cert-manager.svc:443/mutate?timeout=10s\": dial tcp 10.96.191.224:443: connect: connection refused",
                            Field: "",
                        },
                    ],
                    RetryAfterSeconds: 0,
                },
                Code: 500,
            },
        }
        Internal error occurred: failed calling webhook "webhook.cert-manager.io": failed to call webhook: Post "https://cert-manager-webhook.cert-manager.svc:443/mutate?timeout=10s": dial tcp 10.96.191.224:443: connect: connection refused
    occurred

    test/e2e/suite/conformance/certificatesigningrequests/vault/approle.go:182
------------------------------
`

func Test_computeStatsMostFailures(t *testing.T) {
	blocks, err := parseBuildLog([]byte(exampleGingkoBlock5))
	require.NoError(t, err)

	results, err := ginkgoBlocksToGinkgoResults("url", "e2e-v1-13", 1234, 14578011101239, blocks)
	require.NoError(t, err)

	got := computeStatsMostFailures(results)

	assert.Equal(t, []StatsMostFailures{{
		Name:        "[Conformance] Certificates with External Account Binding with issuer type ACME HTTP01 Issuer (Gateway) Creating a Gateway with annotations for issuerRef and other Certificate fields",
		CountPassed: 0,
		CountFailed: 1,
		Errors: []GinkgoResult{{Name: "[Conformance] Certificates with External Account Binding with issuer type ACME HTTP01 Issuer (Gateway) Creating a Gateway with annotations for issuerRef and other Certificate fields",
			Status:   "failed",
			Duration: 300,
			Err:      "timed out waiting for the condition",
			ErrLoc:   "test/e2e/suite/conformance/certificates/tests.go:819",
			Source:   "url#line=20",
			Job:      "e2e-v1-13",
			PR:       1234,
			Build:    14578011101239,
		}}}, {
		Name:        "[Conformance] Certificates with issuer type ACME HTTP01 Issuer (Ingress) Creating a Gateway with annotations for issuerRef and other Certificate fields",
		CountPassed: 0,
		CountFailed: 1,
		Errors: []GinkgoResult{{Name: "[Conformance] Certificates with issuer type ACME HTTP01 Issuer (Ingress) Creating a Gateway with annotations for issuerRef and other Certificate fields",
			Status:   "failed",
			Duration: 300,
			Err:      "timed out waiting for the condition",
			ErrLoc:   "test/e2e/suite/conformance/certificates/tests.go:819",
			Source:   "url#line=38",
			Job:      "e2e-v1-13",
			PR:       1234,
			Build:    14578011101239,
		}}}, {
		Name:        "[Conformance] CertificateSigningRequests CertificateSigningRequest with issuer type Vault AppRole Custom Auth Path ClusterIssuer With Root CA should issue a certificate that defines a Common Name, DNS Name, and sets a duration",
		CountPassed: 0,
		CountFailed: 1,
		Errors: []GinkgoResult{{Name: "[Conformance] CertificateSigningRequests CertificateSigningRequest with issuer type Vault AppRole Custom Auth Path ClusterIssuer With Root CA should issue a certificate that defines a Common Name, DNS Name, and sets a duration",
			Status:   "failed",
			Duration: 46,
			Err:      "failed to create vault issuer\nInternal error occurred: failed calling webhook \"webhook.cert-manager.io\": failed to call webhook: Post \"https://cert-manager-webhook.cert-manager.svc:443/mutate?timeout=10s\": dial tcp 10.96.191.224:443: connect: connection refused",
			ErrLoc:   "test/e2e/suite/conformance/certificatesigningrequests/vault/approle.go:182",
			Source:   "url#line=112",
			Job:      "e2e-v1-13",
			PR:       1234,
			Build:    14578011101239,
		}},
	}}, got)
}

func withBinary(t *testing.T) string {
	start := time.Now()

	bincli, err := gexec.Build("github.com/maelvls/prowdig")
	require.NoError(t, err)

	t.Cleanup(func() {
		gexec.Terminate()
		gexec.CleanupBuildArtifacts()
	})

	t.Logf("compiling binaries took %v, path: %s", time.Since(start).Truncate(time.Second), bincli)
	return bincli
}

type e2ecmd struct {
	*exec.Cmd
	Output *gbytes.Buffer // Both stdout and stderr.
	T      *testing.T
}

func (cmd *e2ecmd) Wait() *e2ecmd {
	_ = cmd.Cmd.Wait()
	return cmd
}

type writeLogger struct {
	prefix string
	w      io.Writer
}

func (l *writeLogger) Write(p []byte) (n int, err error) {
	n, err = l.w.Write(p)
	if err != nil {
		log.Printf("%s %s: %v", l.prefix, string(p[0:n]), err)
	} else {
		log.Printf("%s %s", l.prefix, string(p[0:n]))
	}
	return
}

// createWriterLoggerStr returns a writer that behaves like w except that it
// logs (using log.Printf) each write to standard error, printing the
// prefix and the data written as a string.
//
// Pretty much the same as iotest.NewWriterLogger except it logs strings,
// not hexadecimal jibberish.
func createWriterLoggerStr(prefix string, w io.Writer) io.Writer {
	return &writeLogger{prefix, w}
}

// Runs the passed command and make sure SIGTERM is called on cleanup. Also
// dumps stderr and stdout using log.Printf.
func startWith(t *testing.T, cmd *exec.Cmd) *e2ecmd {
	buff := gbytes.NewBuffer()
	cmd.Stdout = createWriterLoggerStr("stdout", buff)
	cmd.Stderr = createWriterLoggerStr("stderr", buff)

	err := cmd.Start()
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
	})

	return &e2ecmd{Cmd: cmd, Output: buff, T: t}
}

func contents(f io.Reader) string {
	bytes, err := ioutil.ReadAll(f)
	if err != nil {
		panic(err)
	}
	return string(bytes)
}
