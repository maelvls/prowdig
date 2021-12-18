package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_reBuildLogFailures(t *testing.T) {
	matches := reBuildLogFailures.FindAllStringSubmatch(exampleBuildLog, -1)
	assert.Equal(t, [][]string{
		{
			"• Failure [301.574 seconds]\n[Conformance] Certificates\ntest/e2e/framework/framework.go:287\n  with issuer type SelfSigned ClusterIssuer\n  test/e2e/suite/conformance/certificates/tests.go:47\n    should issue an ECDSA, defaulted certificate for a single distinct DNS Name [It]\n    test/e2e/suite/conformance/certificates/suite.go:105\n\n    Unexpected error:\n        <*errors.errorString | 0xc0001c07d0>: {\n            s: \"timed out waiting for the condition\",\n        }\n        timed out waiting for the condition\n    occurred\n\n    test/e2e/suite/conformance/certificates/tests.go:149\n------------------------------\n",
			"301",
			"[Conformance] Certificates",
			"with issuer type SelfSigned ClusterIssuer",
			"should issue an ECDSA, defaulted certificate for a single distinct DNS Name [It]",
			"timed out waiting for the condition",
		},
		{
			"• Failure [0.510 seconds]\n[cert-manager] Approval CertificateRequests\ntest/e2e/framework/framework.go:283\n  a service account with the approve permissions for cluster scoped issuers.example.io/* should be able to deny requests [It]\n  test/e2e/suite/approval/approval.go:225\n\n  Unexpected error:\n      <*errors.StatusError | 0xc0015c0a00>: {\n          ErrStatus: {\n              TypeMeta: {Kind: \"\", APIVersion: \"\"},\n              ListMeta: {\n                  SelfLink: \"\",\n                  ResourceVersion: \"\",\n                  Continue: \"\",\n                  RemainingItemCount: nil,\n              },\n              Status: \"Failure\",\n              Message: \"admission webhook \\\"webhook.cert-manager.io\\\" denied the request: spec.issuerRef: Forbidden: referenced signer resource does not exist\n: {test-issuer Issuer bycbn.example.io}\",\n              Reason: \"NotAcceptable\",\n              Details: nil,\n              Code: 406,\n          },\n      }\n      admission webhook \"webhook.cert-manager.io\" denied the request: spec.issuerRef: Forbidden: referenced signer resource does not exist: {test-issuer Issuer bycbn.example.io}\n  occurred\n\n  test/e2e/suite/approval/approval.go:233\n------------------------------\n",
			"0",
			"[cert-manager] Approval CertificateRequests",
			"a service account with the approve permissions for cluster scoped issuers.example.io/* should be able to deny requests [It]",
			"",
			"admission webhook \"webhook.cert-manager.io\" denied the request: spec.issuerRef: Forbidden: referenced signer resource does not exist: {test-issuer Issuer bycbn.example.io}",
		}}, matches)
}

func Test_parseBuildLogs(t *testing.T) {
	foundTestcases, err := parseBuildLogs([]byte(exampleBuildLog))
	assert.NoError(t, err)
	assert.Equal(t, []testcase{
		{
			duration: 301 * time.Second,
			status:   "failed",
			name:     "[Conformance] Certificates with issuer type SelfSigned ClusterIssuer should issue an ECDSA, defaulted certificate for a single distinct DNS Name",
			err:      "timed out waiting for the condition",
		},
		{
			duration: 0,
			status:   "failed",
			name:     "[cert-manager] Approval CertificateRequests a service account with the approve permissions for cluster scoped issuers.example.io/* should be able to deny requests",
			err:      "admission webhook \"webhook.cert-manager.io\" denied the request: spec.issuerRef: Forbidden: referenced signer resource does not exist: {test-issuer Issuer bycbn.example.io}",
		}},
		foundTestcases)
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
• [SLOW TEST:25.601 seconds]
[Conformance] Certificates
test/e2e/framework/framework.go:287
  with issuer type ACME HTTP01 Issuer (Ingress)
  test/e2e/suite/conformance/certificates/tests.go:47
    should issue a certificate for a single distinct DNS Name defined by an ingress with annotations
    test/e2e/suite/conformance/certificates/suite.go:105
------------------------------
`
