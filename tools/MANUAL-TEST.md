# Manual test: Entra -> STS -> signed request via Cloudflare

Does by hand what the Mule app does, so each hop can be checked on its own.
Use `curl.exe` in PowerShell (plain `curl` there is an alias for something else).

## 1. Get a token from Entra ID

```bash
curl -s -X POST "https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=<CLIENT_ID>" \
  --data-urlencode "client_secret=<CLIENT_SECRET>" \
  --data-urlencode "scope=api://<CLIENT_ID>/.default"
```

Copy `access_token` from the JSON response. Paste it into https://jwt.ms to check `iss`, `aud` and `sub`
against the IAM provider and trust policy.

## 2. Swap it for temporary AWS credentials (STS)

```bash
curl -s -X POST "https://sts.ap-southeast-2.amazonaws.com/" \
  -d "Action=AssumeRoleWithWebIdentity" \
  -d "Version=2011-06-15" \
  -d "RoleArn=<ROLE_ARN>" \
  -d "RoleSessionName=manual-test" \
  -d "DurationSeconds=3600" \
  --data-urlencode "WebIdentityToken=<access_token from step 1>"
```

From the XML response copy `<AccessKeyId>` (starts with `ASIA`), `<SecretAccessKey>` and `<SessionToken>`.
Errors here (`InvalidIdentityToken`, `AccessDenied`) are trust-policy / IdP problems, not signing.

## 3. Sign and send the S3 request through Cloudflare

Set the values as environment variables so they stay out of the command line:

```powershell
$env:AWS_ACCESS_KEY_ID="ASIA..."; $env:AWS_SECRET_ACCESS_KEY="..."; $env:AWS_SESSION_TOKEN="..."
$env:CLOUDFLARE_ACCESS_ID="..."; $env:CLOUDFLARE_ACCESS_SECRET="..."
```
```bash
export AWS_ACCESS_KEY_ID=ASIA... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
export CLOUDFLARE_ACCESS_ID=... CLOUDFLARE_ACCESS_SECRET=...
```

Then (one line):

```
python tools/s3_sign_curl.py PUT data/order-55.json --data "{\"orderId\":55,\"status\":\"PAID\"}" --content-type application/json --signing-host my-bucket.s3.ap-southeast-2.amazonaws.com --cf-host s3-proxy.dev.example.com --show-canonical
```

It prints the canonical request, the signed headers and a ready-to-run curl (bash and PowerShell
versions). Run that curl within ~15 minutes, or add `--send` to run it directly. Read it back with:

```
python tools/s3_sign_curl.py GET data/order-55.json --out order-55.json --signing-host my-bucket.s3.ap-southeast-2.amazonaws.com --cf-host s3-proxy.dev.example.com --send
```

Options: `--file <path>` uploads a file's bytes, `--path-prefix /<bucket>` for path-style hosts,
`--region`, `--unsigned-payload`, and `--cf-host-header` / `--cf-id-header` / `--cf-secret-header` to change
the Cloudflare header names (defaults `cloudFlareHostName`, `cloudFlareAccessId`, `cloudFlareAccessSecret`).

## Reading the result

| Response | Meaning |
|---|---|
| `200` (PUT) with an `ETag` | Signing and Cloudflare forwarding work. If Mule still fails, the difference is in Mule. |
| `SignatureDoesNotMatch` | Compare `--show-canonical` with S3's `<CanonicalRequest>` in the response body: the differing line is what Cloudflare changed. |
| `InvalidAccessKeyId` | The session token did not reach S3. |
| `AccessDenied` | Signature fine; the role's permissions policy does not allow this bucket/key. |
| A Cloudflare page / `401` / `403` without S3 XML | Cloudflare rejected the `cloudFlare*` headers. |
