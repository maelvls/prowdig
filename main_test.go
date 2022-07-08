package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

[91m[1m• Failure [309.036 seconds][0m
[cert-manager] Vault ClusterIssuer CertificateRequest (AppRole)
[90mtest/e2e/framework/framework.go:283[0m
  [91m[1mshould generate a new certificate with Vault configured maximum TTL duration (90 days) when requested duration is greater than TTL [It][0m
  [90mtest/e2e/suite/issuers/vault/certificaterequest/approle.go:215[0m

  [91mUnexpected error:
      <*errors.errorString | 0xc00024a7a0>: {
          s: "timed out waiting for the condition",
      }
      timed out waiting for the condition
  occurred[0m

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
[91m[1m• Failure [71.567 seconds][0m
[cert-manager] Vault Issuer
[90mtest/e2e/framework/framework.go:266[0m
  [91m[1mshould be ready with a valid Kubernetes Role and ServiceAccount Secret [It][0m
  [90mtest/e2e/suite/issuers/vault/issuer.go:180[0m

  [91mUnexpected error:
      <*errors.errorString | 0xc000d55bb0>: {
          s: "timed out waiting for the condition: Last Status: 'False' Reason: 'VaultError', Message: 'Failed to initialize Vault client: error reading Kubernetes service account token from vault-serviceaccount: error calling Vault server: Error making API request.\n\nURL: POST https://vault.e2e-tests-create-vault-issuer-klmxs:8200/v1/auth/kubernetes/login\nCode: 403. Errors:\n\n* permission denied'",
      }
      timed out waiting for the condition: Last Status: 'False' Reason: 'VaultError', Message: 'Failed to initialize Vault client: error reading Kubernetes service account token from vault-serviceaccount: error calling Vault server: Error making API request.
      
      URL: POST https://vault.e2e-tests-create-vault-issuer-klmxs:8200/v1/auth/kubernetes/login
      Code: 403. Errors:
      
      * permission denied'
  occurred[0m

  test/e2e/suite/issuers/vault/issuer.go:200
[90m------------------------------[0m
[91m[1m• Failure in Spec Setup (BeforeEach) [61.637 seconds][0m
[cert-manager] ACME CertificateRequest (HTTP01)
[90mtest/e2e/framework/framework.go:283[0m
  [91m[1mshould automatically recreate challenge pod and still obtain a certificate if it is manually deleted [BeforeEach][0m
  [90mtest/e2e/suite/issuers/acme/certificaterequest/http01.go:207[0m

  [91mUnexpected error:
      <*errors.errorString | 0xc000234850>: {
          s: "timed out waiting for the condition",
      }
      timed out waiting for the condition
  occurred[0m

  test/e2e/suite/issuers/acme/certificaterequest/http01.go:93
[90m------------------------------[0m
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
		}},
	}, {
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
		}},
	},
	}, got)
}
