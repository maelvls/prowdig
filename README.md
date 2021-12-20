# Prow dig

Dig into Prow logs of cert-manager to find which test cases have a timeout too
high compared to the "passed" runs of that test. You must have read access to the
bucket `gs://jetstack-logs` in order to run prowdig. To log in to the bucket, run:

```sh
gcloud auth application-default login
```

I wrote this tool because some Prow jobs in cert-manager would fail after almost
2 hours due to overly large timeouts in tests.

![Screenshot from 2021-12-18 22-49-26](https://user-images.githubusercontent.com/2195781/146656953-6c4f18f3-d273-472d-bac1-e7e4232cea29.png)

Install:

```sh
go install github.com/maelvls/prowdig@latest
```

Run:

```sh
$ prowdig max-duration --limit=20
...
22s     5m8s    [cert-manager] Vault ClusterIssuer CertificateRequest (AppRole) should generate a new certificate valid for the default value (90 days)
14s     5m0s    [Conformance] Certificates with issuer type CA ClusterIssuer Creating a Gateway with annotations for issuerRef and other Certificate fields
14s     5m0s    [Conformance] Certificates with issuer type CA ClusterIssuer should issue a basic, defaulted certificate for a single distinct DNS Name
13s     5m0s    [Conformance] Certificates with issuer type CA ClusterIssuer should issue a CA certificate with the CA basicConstraint set
13s     5m0s    [Conformance] Certificates with issuer type SelfSigned ClusterIssuer should issue a certificate that defines a Common Name and IP Address
12s     5m0s    [Conformance] Certificates with issuer type External ClusterIssuer should issue a certificate that defines a long domain
16s     5m4s    [Conformance] Certificates with issuer type External Issuer should issue another certificate with the same private key if the existing certificate and CertificateRequest are deleted
21s     5m10s   [cert-manager] Vault ClusterIssuer CertificateRequest (AppRole) should generate a new certificate valid for 35 days
11s     5m0s    [Conformance] Certificates with issuer type External Issuer should issue a certificate that defines a Common Name and IP Address
11s     5m0s    [Conformance] Certificates with issuer type CA ClusterIssuer should issue a certificate that defines a distinct DNS Name and another distinct Common Name
11s     5m0s    [Conformance] Certificates with issuer type CA ClusterIssuer should issue a certificate that defines a long domain
11s     5m0s    [Conformance] Certificates with issuer type External ClusterIssuer should issue an ECDSA, defaulted certificate for a single distinct DNS Name
10s     5m0s    [Conformance] Certificates with issuer type External Issuer should issue a basic, defaulted certificate for a single Common Name
10s     5m0s    [Conformance] Certificates with issuer type SelfSigned ClusterIssuer should issue a basic, defaulted certificate for a single Common Name
9s      5m0s    [Conformance] Certificates with issuer type SelfSigned ClusterIssuer should issue a basic, defaulted certificate for a single distinct DNS Name
9s      5m0s    [Conformance] Certificates with issuer type External Issuer should issue an ECDSA, defaulted certificate for a single Common Name
22s     5m12s   [Conformance] Certificates with issuer type External ClusterIssuer should issue another certificate with the same private key if the existing certificate and CertificateRequest are deleted
9s      5m0s    [Conformance] Certificates with issuer type SelfSigned ClusterIssuer should issue an Ed25519, defaulted certificate for a single Common Name
9s      5m1s    [Conformance] Certificates with issuer type SelfSigned ClusterIssuer should issue an ECDSA, defaulted certificate for a single distinct DNS Name
11s     5m3s    [Conformance] Certificates with issuer type CA Issuer should issue another certificate with the same private key if the existing certificate and CertificateRequest are deleted
7s      5m0s    [Conformance] Certificates with issuer type SelfSigned ClusterIssuer should issue an ECDSA, defaulted certificate for a single Common Name
15s     5m13s   [Conformance] Certificates with issuer type SelfSigned Issuer should issue another certificate with the same private key if the existing certificate and CertificateRequest are deleted
32s     10m11s  [Conformance] Certificates with issuer type VaultAppRole ClusterIssuer should issue a certificate that defines a wildcard DNS Name and its apex DNS Name
21s     10m0s   [Conformance] Certificates with issuer type External ClusterIssuer should issue a certificate that defines a wildcard DNS Name and its apex DNS Name
20s     10m0s   [Conformance] Certificates with issuer type External Issuer should issue a certificate that defines a wildcard DNS Name and its apex DNS Name
```

prowdig displays the test cases for the jobs from the 20 last PRs. The format
is:

```plain
24s     5m9s    [cert-manager] Vault ClusterIssuer CertificateRequest...
^        ^      ^
|        |      The test name.
|        |
|        Max. duration of "passed".
|
Max. duration of "failed".
```

prowdig displays test cases by ascending order of priority ("priority" meaning
that you should take a look at this test case). The last test case displayed is
the one with the highest difference between the max. duration of "passed" and
max. duration of "failed". The test cases for which no "failed" result are not
displayed.

Since the build-log.txt files large (can go up to 36MB in case of many timeouts,
which is around 600MB for 20 PRs which account for 476 `build-log.txt` files),
prowdig caches the files in `~/.cache/prowdig`. This folder may get big, feel
free to delete it when you are done:

```sh
rm -rf ~/.cache/prowdig
```

prowdig works by fetching the `junit__xx.xml` files from the jobs of the last 20
PRs. But there is a caveat to it: the junit files are only uploaded when the
Prow job finishes before the job's timeout (which about 2 hours). Which means
that in order to find out which tests have timed out, we have to look at the raw
build-log.txt and parse errors of the form:

```plain
• Failure [301.437 seconds]
[Conformance] Certificates
test/e2e/framework/framework.go:287
  with issuer type External ClusterIssuer
  test/e2e/suite/conformance/certificates.go:47
    should issue a cert with wildcard DNS Name [It]
    test/e2e/suite/conformance/certificates.go:105
    Unexpected error:

        <*errors.errorString | 0xc0001c07b0>: {
            s: "timed out waiting for the condition",
        }
        timed out waiting for the condition
    occurred
    test/e2e/suite/conformance/certificates.go:522
------------------------------
```

If you would like to list the Ginkgo failures that happened
in a given file (can be a URL), you can run:

```
prowdig parse-logs https://storage.googleapis.com/jetstack-logs/pr-logs/pull/jetstack_cert-manager/4044/pull-cert-manager-e2e-v1-21/1395667201859522561/build-log.txt
```

That will show you an overview of the failures:

```
31s     [cert-manager] CertificateRequest with a properly configured Issuer should obtain a signed certificate for a single domain: timed out waiting for the condition
1m9s    [cert-manager] Vault Issuer should be ready with a valid Kubernetes Role and ServiceAccount Secret: timed out waiting for the condition: Last Status: 'False' Reason: 'VaultError', Message: 'Failed to initialize Vault client: error reading Kubernetes service account token from vault-serviceaccount: error calling Vault server: Error making API request.

URL: POST https://vault.e2e-tests-create-vault-issuer-pgvs6:8200/v1/auth/kubernetes/login
Code: 403. Errors:

* permission denied'
1m11s   [cert-manager] Vault Issuer should be ready with a valid Kubernetes Role and ServiceAccount Secret: timed out waiting for the condition: Last Status: 'False' Reason: 'VaultError', Message: 'Failed to initialize Vault client: error reading Kubernetes service account token from vault-serviceaccount: error calling Vault server: Error making API request.

URL: POST https://vault.e2e-tests-create-vault-issuer-klmxs:8200/v1/auth/kubernetes/login
Code: 403. Errors:

* permission denied'
```
