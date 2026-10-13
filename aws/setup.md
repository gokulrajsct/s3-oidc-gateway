# AWS + Entra ID setup for OIDC federation

Replace the `<PLACEHOLDERS>` in the JSON files in this folder first.

## 1. Entra ID

1. App registrations -> New registration (single tenant). Note the **Application (client) ID** and **Directory (tenant) ID**.
2. Manifest -> set `"requestedAccessTokenVersion": 2` under `api`.
   This makes tokens v2.0: `iss = https://login.microsoftonline.com/<TENANT_ID>/v2.0`, `aud = <CLIENT_ID>`.
3. Certificates & secrets -> create a client secret (or, better, upload a certificate and switch the
   token request to a signed client assertion). Put the secret in `ENTRA_CLIENT_SECRET`.
4. Find the **Object ID of the service principal** (Enterprise applications -> your app -> Object ID).
   For client-credentials tokens the `sub` claim is this value. Confirm with a real token at https://jwt.ms.

## 2. AWS IAM

```bash
# OIDC identity provider (once per account)
aws iam create-open-id-connect-provider \
  --url https://login.microsoftonline.com/<TENANT_ID>/v2.0 \
  --client-id-list <CLIENT_ID>

# Role + trust policy
aws iam create-role --role-name mule-s3-oidc-role \
  --assume-role-policy-document file://aws/trust-policy.json \
  --max-session-duration 3600

# Least-privilege S3 access
aws iam put-role-policy --role-name mule-s3-oidc-role \
  --policy-name s3-object-rw --policy-document file://aws/permissions-policy.json
```

Put the role ARN in `aws.roleArn` of `config-<env>.yaml`.

Always pin `sub` in the trust policy. With only `aud`, any application in your tenant that can
obtain a token for this audience could assume the role.

## 3. Quick checks

```bash
# Does the exchange work? (token from Entra in $JWT)
aws sts assume-role-with-web-identity --role-arn <ROLE_ARN> \
  --role-session-name test --web-identity-token "$JWT"
```

| Error from STS            | Usual cause                                                           |
|---------------------------|-----------------------------------------------------------------------|
| `InvalidIdentityToken`    | `iss`/`aud` do not match the IAM provider (v1 vs v2 token mix-up)     |
| `AccessDenied` on assume  | `sub` or `aud` condition in the trust policy does not match the token |
| `ExpiredTokenException`   | clock skew on the Mule runtime                                        |
