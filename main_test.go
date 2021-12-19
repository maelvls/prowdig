package main

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_reGinkgoBlock(t *testing.T) {
	block, err := parseGinkgoBlock(ginkgoBlock{line: 42, lines: strings.Split(exampleGingkoBlock1, "\n")})
	assert.NoError(t, err)
	assert.Equal(t, ginkgoResult{
		Name:        "[cert-manager] Approval CertificateRequests a service account with the approve permissions for cluster scoped issuers.example.io/* should be able to deny requests",
		Status:      "failed",
		Duration:    0 * time.Second,
		Err:         "admission webhook \"webhook.cert-manager.io\" denied the request: spec.issuerRef: Forbidden: referenced signer resource does not exist: {test-issuer Issuer bycbn.example.io}",
		ErrLocation: "test/e2e/suite/approval/approval.go:233",
	}, block)

	block, err = parseGinkgoBlock(ginkgoBlock{line: 123, lines: strings.Split(exampleGingkoBlock2, "\n")})
	assert.NoError(t, err)
	assert.Equal(t, ginkgoResult{
		Name:        "[Conformance] Certificates with issuer type SelfSigned ClusterIssuer should issue an ECDSA, defaulted certificate for a single distinct DNS Name",
		Status:      "failed",
		Duration:    301 * time.Second,
		Err:         "timed out waiting for the condition",
		ErrLocation: "test/e2e/suite/conformance/certificates/tests.go:149",
	}, block)

	block, err = parseGinkgoBlock(ginkgoBlock{line: 123, lines: strings.Split(exampleGingkoBlock3, "\n")})
	assert.NoError(t, err)
	assert.Equal(t, ginkgoResult{
		Name:        "[cert-manager] Certificate SecretTemplate should update the values of keys that have been modified in the SecretTemplate",
		Status:      "failed",
		Duration:    6 * time.Second,
		Err:         "Timed out after 5.000s.\nExpected\n    <map[string]string | len:10>: {\n        \"foo\": \"bar\",\n        \"bar\": \"foo\",\n        \"cert-manager.io/ip-sans\": \"\",\n        \"cert-manager.io/issuer-group\": \"cert-manager.io\",\n        \"cert-manager.io/issuer-kind\": \"Issuer\",\n        \"cert-manager.io/issuer-name\": \"certificate-secret-template\",\n        \"cert-manager.io/uri-sans\": \"\",\n        \"cert-manager.io/alt-names\": \"\",\n        \"cert-manager.io/certificate-name\": \"test-secret-template-qbwsc\",\n        \"cert-manager.io/common-name\": \"test\",\n    }\nto have {key: value}\n    <map[interface {}]interface {} | len:1>: {\n        <string>\"foo\": <string>\"123\",\n    }",
		ErrLocation: "test/e2e/suite/secrettemplate/secrettemplate.go:202",
	}, block)
}

func Test_parseBuildLog(t *testing.T) {
	blocks, err := parseBuildLog([]byte(exampleBuildLog))
	assert.NoError(t, err)
	assert.Len(t, blocks, 5)

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
