# s3-oidc-gateway

Mule 4 application that reads and writes S3 objects **through Cloudflare** using short-lived
credentials obtained with **OIDC (AssumeRoleWithWebIdentity)** instead of a static access key and
secret. The S3 connector is not used; requests are SigV4-signed in Java and sent with the HTTP connector.

```
Mule --1. client_credentials--> Entra ID --> JWT
Mule --2. AssumeRoleWithWebIdentity(JWT)--> AWS STS --> temp key / secret / session token (~1h, cached ~55 min)
Mule --3. SigV4 sign (+ x-amz-security-token)--> Cloudflare --> S3
```

## Layout

| Path | Purpose |
|------|---------|
| `src/main/mule/global-config.xml` | Properties, HTTP listener, Entra / STS / Cloudflare request configs, credentials object store |
| `src/main/mule/aws-credentials.xml` | `get-aws-credentials` (cache) and `exchange-oidc-for-aws-creds` (Entra -> STS) |
| `src/main/mule/s3-operations.xml` | `s3-sign-request`, `s3-put-object`, `s3-get-object` - reuse these from your own flows |
| `src/main/mule/api.xml` | `PUT/GET /objects/<key>` facade + global error handler (so you can test end to end) |
| `src/main/java/com/acme/aws/S3SigV4Signer.java` | SigV4 signer (same algorithm as before, plus session token) |
| `src/test/java/.../S3SigV4SignerTest.java` | Unit tests using AWS's published SigV4 examples |
| `src/main/resources/config-{dev,prod}.yaml` | Per-environment configuration |
| `aws/` | Trust policy, permissions policy and setup steps for IAM + Entra |

## Configure

1. Follow `aws/setup.md` (Entra app registration, IAM OIDC provider, role).
2. Fill in the `TODO` values in `src/main/resources/config-dev.yaml`.
3. Provide the Entra secret at runtime, never in the file:
   `ENTRA_CLIENT_SECRET=... ` (environment variable) or `-DENTRA_CLIENT_SECRET=...`.
   For CloudHub 2.0 use a secret / property in the deployment. A client certificate assertion is preferable to a secret.

## Build, run, test

```bash
mvn clean package                    # runs the signer unit tests, builds the Mule app
mvn clean package -DskipTests

# Anypoint Studio / Mule runtime:  -Dmule.env=dev  and  ENTRA_CLIENT_SECRET in the environment

curl -X PUT  --data-binary @invoice.pdf -H 'Content-Type: application/pdf' http://localhost:8081/objects/invoices/invoice.pdf
curl -o out.pdf                                                             http://localhost:8081/objects/invoices/invoice.pdf
```

## Cloudflare Access credentials

Every call to Cloudflare carries the Access service-token headers, configured under `cloudflare.auth`
in `config-<env>.yaml` (header names default to `CF-Access-Client-Id` / `CF-Access-Client-Secret`;
rename them if your Cloudflare layer expects different ones). Supply the values at runtime:
`CLOUDFLARE_ACCESS_ID` and `CLOUDFLARE_ACCESS_SECRET` (environment variables / secure deployment
properties). They are not part of the SigV4 signature.

## What the Cloudflare layer must do

Mule connects to `cloudflare.host`, but the signature is computed for `s3.signingHost`
(e.g. `my-bucket.s3.ap-southeast-2.amazonaws.com`). This is the same arrangement as the static-key
version: Cloudflare has to forward the request to S3 with `Host: <s3.signingHost>`, the same path
and query string, and **must not alter** `Authorization`, `x-amz-date`, `x-amz-content-sha256`,
`x-amz-security-token` or `content-type`. Only these headers (plus `host`) are signed, so headers
Cloudflare adds or removes elsewhere cannot break the signature.

The only thing that changes for Cloudflare compared with static keys is the extra
`x-amz-security-token` header, so make sure it is passed through (if it uses an allow-list of headers, add it).

## Behaviour notes

- **Credential cache**: in-memory object store, 55 min TTL, plus a 5 min safety margin on `expiresAt`. Each replica keeps its own copy.
- **Payload hash**: DataWeave computes SHA-256 of the body (`aws.signPayload: "true"`). Set it to `"false"` to sign `UNSIGNED-PAYLOAD` for very large objects; the PUT request is sent with `requestStreamingMode="NEVER"` (S3 needs Content-Length), so the body is still buffered by the HTTP client.
- **Object keys**: keys containing `..` or `//` are rejected. Keep keys to simple characters until you have tested your Cloudflare route with special ones (see below).
- **Errors**: 401/403/400 from Entra, STS, Cloudflare or S3 are logged in detail and returned to the caller as a generic 502. 404 maps to 404.

## Not verified here

- The signer is verified against AWS's three documented SigV4 test vectors (GET with Range, PUT with storage class and an encoded key, GET with a query string).
- The Mule project itself could **not** be built or run in the environment that generated it (no access to MuleSoft's Maven repository), so the XML is checked for well-formedness only. On first build:
  - confirm or bump the dependency versions in `pom.xml` (`app.runtime`, connectors, `mule-maven-plugin`);
  - test an object key with a space, `+` or non-ASCII character. The signer URI-encodes the key once and the same encoded path is given to the HTTP requester; if the S3 response is `SignatureDoesNotMatch` for those keys only, the requester is encoding `%` again;
  - decode a real Entra token (https://jwt.ms) and compare `iss`, `aud` and `sub` with the IAM provider and trust policy.

## Debugging SignatureDoesNotMatch

S3 returns the canonical request it computed in the error body (`<CanonicalRequest>`); the app logs
that body at ERROR (`Upstream call failed ... HTTP:FORBIDDEN`). Set `aws.debugSigning: "true"` to also
log, at WARN, the canonical request Mule signed (token masked), then compare the two line by line:
method, path, host, each header and the payload hash. Whatever differs is what Cloudflare (or the
config) changed. Turn the switch off again afterwards.

## Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| `SignatureDoesNotMatch` | Cloudflare changes host, path (double slashes, encoding) or drops `x-amz-security-token`; clock skew |
| `InvalidIdentityToken` | IAM provider URL / audience does not match the token `iss` / `aud` (v1 vs v2 token) |
| `AccessDenied` on STS | Trust policy `sub` / `aud` condition does not match the token |
| `ExpiredToken` from S3 | Cached credentials outlived the session; check clock and the 55 min TTL |
