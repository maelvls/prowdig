# Prow dig

Dig into Prow logs of cert-manager to find which test cases have a timeout too
high compared to the passed runs of that test. You must have read access to the
bucket `gs://jetstack-logs` in order to run this prowdig.

Install:

```sh
go install github.com/maelvls/prowdig@latest
```

Run:

```sh
$ prowdig
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