#!/usr/bin/env python3
"""
Manual test of what the Mule app does in its last step: SigV4-sign an S3 request for the S3 host,
then print (and optionally run) the curl command that sends it to Cloudflare with the Cloudflare
headers. Standard library only. Same algorithm as src/main/java/com/acme/aws/S3SigV4Signer.java.

Prerequisites: temporary credentials from STS (see tools/MANUAL-TEST.md, steps 1 and 2).
Pass them as arguments or, to keep them out of shell history, as environment variables:
    AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN,
    CLOUDFLARE_ACCESS_ID, CLOUDFLARE_ACCESS_SECRET

Examples
    python tools/s3_sign_curl.py PUT data/order-55.json --data "{\"orderId\":55,\"status\":\"PAID\"}" ^
        --content-type application/json --signing-host my-bucket.s3.ap-southeast-2.amazonaws.com ^
        --cf-host s3-proxy.dev.example.com
    python tools/s3_sign_curl.py PUT invoices/invoice-1001.pdf --file invoice-1001.pdf --content-type application/pdf ...
    python tools/s3_sign_curl.py GET data/order-55.json --out order-55.json ...
Add --send to run the curl straight away, --show-canonical to print what was signed.
"""
import argparse, datetime, hashlib, hmac, os, shlex, subprocess, sys, tempfile

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
UNRESERVED = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~")


def uri_encode(s):
    return "".join(chr(b) if b in UNRESERVED else "%%%02X" % b for b in s.encode("utf-8"))


def encode_path(path):
    """Each segment encoded once, '/' kept (S3 rule). Same as S3SigV4Signer.encodePath."""
    if not path:
        return "/"
    enc = "/".join(uri_encode(seg) for seg in path.split("/"))
    return enc if enc.startswith("/") else "/" + enc


def _hmac(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def sign(method, host, uri, query, region, payload_hash, ak, sk, token, now):
    amz_date, date = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    headers = {"host": host, "x-amz-content-sha256": payload_hash, "x-amz-date": amz_date}
    if token:
        headers["x-amz-security-token"] = token
    names = sorted(headers)
    canonical_headers = "".join(f"{n}:{' '.join(headers[n].split())}\n" for n in names)
    signed_headers = ";".join(names)
    canonical_request = "\n".join([method, uri, query, canonical_headers, signed_headers, payload_hash])
    scope = f"{date}/{region}/s3/aws4_request"
    string_to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope,
                                hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()])
    k = _hmac(("AWS4" + sk).encode("utf-8"), date)
    k = _hmac(_hmac(_hmac(k, region), "s3"), "aws4_request")
    signature = hmac.new(k, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    out = {
        "Authorization": f"AWS4-HMAC-SHA256 Credential={ak}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        "x-amz-date": amz_date,
        "x-amz-content-sha256": payload_hash,
    }
    if token:
        out["x-amz-security-token"] = token
    return out, canonical_request, string_to_sign


def need(value, env, name):
    v = value or os.environ.get(env)
    if not v:
        sys.exit(f"missing {name}: pass it as an argument or set {env}")
    return v


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("method", choices=["PUT", "GET"])
    p.add_argument("key", help="object key, unencoded, e.g. data/order-55.json")
    body = p.add_mutually_exclusive_group()
    body.add_argument("--file", help="PUT: file whose bytes are uploaded")
    body.add_argument("--data", help="PUT: literal body (written to a temp file so the bytes are exact)")
    p.add_argument("--content-type", default="application/octet-stream")
    p.add_argument("--out", help="GET: save the object here (default: print to stdout)")
    p.add_argument("--signing-host", required=True, help="S3 host to sign = s3.signingHost")
    p.add_argument("--path-prefix", default="", help='s3.pathPrefix ("" or "/<bucket>" for path style)')
    p.add_argument("--region", default="ap-southeast-2")
    p.add_argument("--unsigned-payload", action="store_true", help="sign UNSIGNED-PAYLOAD instead of the body hash")
    p.add_argument("--ak"); p.add_argument("--sk"); p.add_argument("--token")
    p.add_argument("--cf-host", required=True, help="Cloudflare host Mule connects to = cloudflare.host")
    p.add_argument("--cf-scheme", default="https")
    p.add_argument("--cf-id"); p.add_argument("--cf-secret")
    p.add_argument("--cf-host-header", default="cloudFlareHostName")
    p.add_argument("--cf-id-header", default="cloudFlareAccessId")
    p.add_argument("--cf-secret-header", default="cloudFlareAccessSecret")
    p.add_argument("--timestamp", help=argparse.SUPPRESS)          # fixed time, for tests
    p.add_argument("--show-canonical", action="store_true")
    p.add_argument("--send", action="store_true", help="run the curl command now")
    a = p.parse_args(argv)

    ak = need(a.ak, "AWS_ACCESS_KEY_ID", "access key id")
    sk = need(a.sk, "AWS_SECRET_ACCESS_KEY", "secret access key")
    token = need(a.token, "AWS_SESSION_TOKEN", "session token")
    cf_id = need(a.cf_id, "CLOUDFLARE_ACCESS_ID", "Cloudflare access id")
    cf_secret = need(a.cf_secret, "CLOUDFLARE_ACCESS_SECRET", "Cloudflare access secret")

    body_file = None
    if a.method == "PUT":
        if a.data is not None:
            fd, body_file = tempfile.mkstemp(prefix="s3body-")
            with os.fdopen(fd, "wb") as f:
                f.write(a.data.encode("utf-8"))
        elif a.file:
            body_file = a.file
        else:
            sys.exit("PUT needs --file or --data")
        content = open(body_file, "rb").read()
        payload_hash = "UNSIGNED-PAYLOAD" if a.unsigned_payload else hashlib.sha256(content).hexdigest()
    else:
        payload_hash = EMPTY_SHA256

    now = (datetime.datetime.strptime(a.timestamp, "%Y%m%dT%H%M%SZ") if a.timestamp
           else datetime.datetime.now(datetime.timezone.utc))
    path = encode_path(a.path_prefix + "/" + a.key)
    signed, canonical, sts = sign(a.method, a.signing_host, path, "", a.region, payload_hash, ak, sk, token, now)

    headers = dict(signed)
    headers[a.cf_host_header] = a.signing_host      # Cloudflare forwards to the host that was signed
    headers[a.cf_id_header] = cf_id
    headers[a.cf_secret_header] = cf_secret
    if a.method == "PUT":
        headers["Content-Type"] = a.content_type

    cmd = ["curl", "-sS", "-i", "--path-as-is", "-X", a.method, f"{a.cf_scheme}://{a.cf_host}{path}"]
    for k, v in headers.items():
        cmd += ["-H", f"{k}: {v}"]
    if a.method == "PUT":
        cmd += ["--data-binary", "@" + body_file]
    elif a.out:
        cmd += ["-o", a.out]

    if a.show_canonical:
        print("---- canonical request (what was signed) ----\n" + canonical)
        print("---- string to sign ----\n" + sts + "\n")
    print("---- signed headers ----")
    for k, v in signed.items():
        print(f"{k}: {v}")
    print(f"\n---- curl (valid for ~15 minutes, x-amz-date {signed['x-amz-date']}) ----")
    print("bash/zsh:   " + " ".join(shlex.quote(c) for c in cmd))
    print("PowerShell: " + " ".join(["curl.exe"] + ["'" + c.replace("'", "''") + "'" for c in cmd[1:]]))
    print("\nThe command contains live credentials: do not paste it into tickets or chat.")

    if a.send:
        print("\n---- response ----", flush=True)
        return subprocess.call(cmd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
