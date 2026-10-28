"""
Usage (from the project root, needs Java 17 and Python 3):
    mvn -q test-compile
    pip install botocore
    python3 tools/sigv4_e2e_check.py target/classes:target/test-classes      (use ; instead of : on Windows)

End-to-end check of the signing path, using botocore (AWS's own SigV4 implementation) as the
"S3" that verifies the request.

    Mule  (S3SigV4Signer + header assembly exactly as in s3-operations.xml)
      -> Cloudflare  (simulated: Host := cloudFlareHostName header, cloudFlare* headers removed,
                      path / query / every other header forwarded untouched)
      -> S3          (simulated: recompute the signature from what it received, like S3 does)
"""
import hashlib, re, subprocess, sys, time
from botocore.auth import S3SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.utils import percent_encode

CP = sys.argv[1]                        # classpath with S3SigV4Signer + SignCli
AK, SK = "ASIAEXAMPLEEXAMPLE12", "tempSecretKey/EXAMPLE+abc123/xyz=="
TOKEN = "IQoJb3JpZ2luX2VjEXAMPLE//////////wEaDmFwLXNvdXRoZWFzdC0yIkcwRQIh+EXAMPLE=="
REGION = "ap-southeast-2"
CF_HOST = "s3-proxy.dev.example.com"
EMPTY = hashlib.sha256(b"").hexdigest()

# Cloudflare header names as the user's Cloudflare layer expects them
H_HOST, H_ID, H_SECRET = "cloudFlareHostName", "cloudFlareAccessId", "cloudFlareAccessSecret"


def mule_sign(method, signing_host, key, prefix, payload_hash, now):
    line = "\t".join([method, signing_host, key, prefix, REGION, payload_hash, AK, SK, TOKEN, str(now)])
    out = subprocess.run(["java", "-cp", CP, "com.acme.aws.SignCli"], input=line + "\n",
                         capture_output=True, text=True, check=True).stdout.strip().split("\t")
    return out[0], dict(kv.split("=", 1) for kv in out[1:])


def mule_outbound(method, signing_host, key, prefix, body, sign_payload=True, now=None):
    """What Mule sends to Cloudflare (mirrors s3-sign-request + s3-put-object / s3-get-object)."""
    now = now or int(time.time())
    if method == "PUT":
        payload_hash = hashlib.sha256(body).hexdigest() if sign_payload else "UNSIGNED-PAYLOAD"
    else:
        payload_hash, body = EMPTY, b""
    path, signed = mule_sign(method, signing_host, key, prefix, payload_hash, now)
    headers = dict(signed)                                  # vars.signedHeaders
    headers.update({H_ID: "cf-id-123", H_SECRET: "cf-secret-456", H_HOST: signing_host})  # ++ cf
    if method == "PUT":
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(body))
    headers["Host"] = CF_HOST                               # set by Mule's HTTP requester
    headers["User-Agent"] = "AHC/2.1"                       # also added by the requester, unsigned
    return {"method": method, "path": path, "headers": headers, "body": body}


def cloudflare(req, replace_host=True, path_rewrite=None, drop=()):
    h = {k: v for k, v in req["headers"].items() if k not in (H_ID, H_SECRET, H_HOST)}
    if replace_host:
        h["Host"] = req["headers"][H_HOST]
    for d in drop:
        h.pop(d, None)
    path = path_rewrite(req["path"]) if path_rewrite else req["path"]
    return {**req, "headers": h, "path": path}


def s3_verify(req):
    """Return (ok, reason). Recomputes the signature the way S3 does: from the received request,
    using only the headers listed in SignedHeaders, with botocore's SigV4 implementation."""
    hdr = {k.lower(): v for k, v in req["headers"].items()}
    m = re.match(r"AWS4-HMAC-SHA256 Credential=([^/]+)/(\d{8})/([^/]+)/s3/aws4_request, "
                 r"SignedHeaders=([^,]+), Signature=([0-9a-f]{64})$", hdr["authorization"])
    if not m:
        return False, "malformed Authorization"
    ak, date, region, signed_names, provided = m.groups()
    signed_names = signed_names.split(";")
    if "x-amz-security-token" not in hdr:
        return False, "InvalidAccessKeyId (no session token)"
    for name in hdr:                                   # S3 rule: every x-amz-* header must be signed
        if name.startswith("x-amz-") and name not in signed_names:
            return False, f"unsigned x-amz header {name}"
    for name in signed_names:
        if name not in hdr:
            return False, f"signed header {name} missing from request"
    if hdr["x-amz-content-sha256"] not in ("UNSIGNED-PAYLOAD",) and \
            hdr["x-amz-content-sha256"] != hashlib.sha256(req["body"]).hexdigest():
        return False, "XAmzContentSHA256Mismatch"

    r = AWSRequest(method=req["method"], url=f"https://{hdr['host']}{req['path']}",
                   headers={n: hdr[n] for n in signed_names}, data=req["body"])
    r.context["timestamp"] = hdr["x-amz-date"]
    auth = S3SigV4Auth(Credentials(ak, SK, TOKEN), "s3", region)
    cr = auth.canonical_request(r)
    expected = auth.signature(auth.string_to_sign(r, cr), r)
    return (expected == provided), ("signature OK" if expected == provided else
                                    "SignatureDoesNotMatch\n--- S3 canonical request ---\n" + cr)


CASES = [
    # (name, method, signingHost, key, pathPrefix, body, signPayload)
    ("PUT json, virtual-hosted", "PUT", "my-bucket.s3.ap-southeast-2.amazonaws.com", "data/order-55.json", "",
     b'{"orderId":55,"status":"PAID"}', True),
    ("PUT pdf bytes, virtual-hosted", "PUT", "my-bucket.s3.ap-southeast-2.amazonaws.com", "invoices/2026/invoice-1001.pdf", "",
     bytes(range(256)) * 40, True),
    ("PUT UNSIGNED-PAYLOAD", "PUT", "my-bucket.s3.ap-southeast-2.amazonaws.com", "big/file.bin", "",
     b"x" * 5000, False),
    ("PUT path-style with bucket prefix", "PUT", "s3.ap-southeast-2.amazonaws.com", "data/order-55.json", "/my-bucket",
     b'{"a":1}', True),
    ("PUT key with space, +, $, =, unicode", "PUT", "my-bucket.s3.ap-southeast-2.amazonaws.com",
     "reports/Q3 summary+final$v=2 é.pdf", "", b"%PDF-1.7 test", True),
    ("PUT empty body", "PUT", "my-bucket.s3.ap-southeast-2.amazonaws.com", "empty.txt", "", b"", True),
    ("GET object", "GET", "my-bucket.s3.ap-southeast-2.amazonaws.com", "data/order-55.json", "", b"", True),
    ("GET key with unicode", "GET", "my-bucket.s3.ap-southeast-2.amazonaws.com", "folder/é ü.txt", "", b"", True),
]

fails = 0
print("== Positive cases: Cloudflare swaps Host from cloudFlareHostName, forwards everything else ==")
for name, method, host, key, prefix, body, sp in CASES:
    req = mule_outbound(method, host, key, prefix, body, sp)
    # 1. path Mule sends must be what botocore would put on the wire for this key
    want_path = percent_encode(prefix + "/" + key, safe="/~")
    enc_ok = req["path"] == want_path
    ok, why = s3_verify(cloudflare(req))
    status = "PASS" if (ok and enc_ok) else "FAIL"
    fails += status == "FAIL"
    print(f"{status}  {name:42s} path={req['path']}  {why}{'' if enc_ok else '  (encoding differs from botocore: ' + want_path + ')'}")

print("\n== Negative cases: must be rejected (proves the check is sensitive) ==")
base = mule_outbound("PUT", "my-bucket.s3.ap-southeast-2.amazonaws.com", "data/order-55.json", "", b'{"x":1}')
NEG = [
    ("Cloudflare keeps its own Host", cloudflare(base, replace_host=False), "SignatureDoesNotMatch"),
    ("Cloudflare adds /uploads to path", cloudflare(base, path_rewrite=lambda p: "/uploads" + p), "SignatureDoesNotMatch"),
    ("Cloudflare drops x-amz-security-token", cloudflare(base, drop=("x-amz-security-token",)), "InvalidAccessKeyId"),
    ("Body changed in transit", {**cloudflare(base), "body": b'{"x": 1}'}, "XAmzContentSHA256Mismatch"),
    ("x-amz-date rewritten", cloudflare({**base, "headers": {**base["headers"], "x-amz-date": "20261028T000000Z"}}),
     "SignatureDoesNotMatch"),
]
for name, req, expect in NEG:
    ok, why = s3_verify(req)
    status = "PASS" if (not ok and why.startswith(expect)) else "FAIL"
    fails += status == "FAIL"
    print(f"{status}  {name:42s} -> {why.splitlines()[0]}")

print("\nALL OK" if fails == 0 else f"\n{fails} FAILED")
sys.exit(1 if fails else 0)
