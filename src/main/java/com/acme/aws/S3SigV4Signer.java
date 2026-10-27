package com.acme.aws;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * AWS Signature Version 4 signer for S3, used by the Mule flows because the
 * native S3 connector cannot be used (requests go through Cloudflare).
 *
 * Differences from the old static-key signer:
 *  - credentials are the TEMPORARY ones obtained via AssumeRoleWithWebIdentity,
 *    so the session token is signed as the {@code x-amz-security-token} header;
 *  - the body is NOT passed in. Mule hashes it in DataWeave and passes
 *    {@code payloadHash} (or {@link #UNSIGNED_PAYLOAD}), so no payload is
 *    buffered or converted here.
 *
 * Request map (all values are strings except {@code headers}):
 * <pre>
 *   method            GET | PUT | ...
 *   host              host to sign - must equal the Host header S3 finally receives
 *   uri               canonical URI, ALREADY URI-encoded (see {@link #encodePath(String)})
 *   query             canonical query string, "" if none (see {@link #canonicalQueryString(Map)})
 *   region            e.g. ap-southeast-2
 *   payloadHash       lower-case hex SHA-256 of the body, or UNSIGNED-PAYLOAD
 *   accessKeyId       temporary access key id
 *   secretAccessKey   temporary secret access key
 *   sessionToken      temporary session token (optional, but required for STS credentials)
 *   headers           (optional) extra headers to sign, e.g. content-type, range.
 *                     The caller MUST send these exact headers.
 * </pre>
 *
 * Returns the headers the caller must add to the outgoing request
 * (Authorization, x-amz-date, x-amz-content-sha256, x-amz-security-token).
 * The Host header is deliberately not returned: it is set by the HTTP client.
 */
public final class S3SigV4Signer {

    public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";

    private static final String ALGORITHM = "AWS4-HMAC-SHA256";
    private static final String SERVICE = "s3";
    private static final DateTimeFormatter AMZ_DATE = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'");
    private static final DateTimeFormatter DATE_STAMP = DateTimeFormatter.ofPattern("yyyyMMdd");
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private S3SigV4Signer() {
    }

    /** Entry point used by the Mule Java module. */
    public static Map<String, String> sign(Map<String, Object> req) {
        return signAt(req, Clock.systemUTC());
    }

    /** Same as {@link #sign(Map)} with an injectable clock (used by the unit tests). */
    static Map<String, String> signAt(Map<String, Object> req, Clock clock) {
        return compute(req, clock).headers;
    }

    /**
     * Debug aid: the canonical request that {@link #sign(Map)} would sign, with the session token
     * masked. Compare it line by line with the {@code <CanonicalRequest>} S3 returns in a
     * SignatureDoesNotMatch error. Only the x-amz-date line can legitimately differ.
     */
    public static String describe(Map<String, Object> req) {
        return describeAt(req, Clock.systemUTC());
    }

    static String describeAt(Map<String, Object> req, Clock clock) {
        Signed s = compute(req, clock);
        String masked = s.canonicalRequest.replaceAll("(?m)^x-amz-security-token:.*$", "x-amz-security-token:<masked>");
        return masked + "\n--- credential scope: " + s.scope;
    }

    private static final class Signed {
        final String canonicalRequest;
        final String scope;
        final Map<String, String> headers;

        Signed(String canonicalRequest, String scope, Map<String, String> headers) {
            this.canonicalRequest = canonicalRequest;
            this.scope = scope;
            this.headers = headers;
        }
    }

    private static Signed compute(Map<String, Object> req, Clock clock) {
        String method = required(req, "method").toUpperCase(Locale.ROOT);
        String host = required(req, "host");
        String uri = required(req, "uri");
        String query = optional(req, "query");
        String region = required(req, "region");
        String payloadHash = required(req, "payloadHash");
        String accessKey = required(req, "accessKeyId");
        String secretKey = required(req, "secretAccessKey");
        String token = optional(req, "sessionToken");

        ZonedDateTime now = ZonedDateTime.now(clock.withZone(ZoneOffset.UTC));
        String amzDate = now.format(AMZ_DATE);
        String dateStamp = now.format(DATE_STAMP);

        // Headers to sign: lower-case names, sorted. Keep the set small so that headers
        // Cloudflare adds or removes (cf-*, x-forwarded-*, ...) cannot invalidate the signature.
        TreeMap<String, String> headers = new TreeMap<>();
        headers.put("host", host);
        headers.put("x-amz-content-sha256", payloadHash);
        headers.put("x-amz-date", amzDate);
        if (!token.isEmpty()) {
            headers.put("x-amz-security-token", token);
        }
        Object extra = req.get("headers");
        if (extra instanceof Map) {
            for (Map.Entry<?, ?> e : ((Map<?, ?>) extra).entrySet()) {
                if (e.getKey() == null || e.getValue() == null) {
                    continue;
                }
                String name = String.valueOf(e.getKey()).toLowerCase(Locale.ROOT).trim();
                if (name.equals("authorization") || name.equals("host")) {
                    continue;
                }
                headers.put(name, normalizeHeaderValue(String.valueOf(e.getValue())));
            }
        }

        StringBuilder canonicalHeaders = new StringBuilder();
        for (Map.Entry<String, String> e : headers.entrySet()) {
            canonicalHeaders.append(e.getKey()).append(':').append(e.getValue()).append('\n');
        }
        String signedHeaders = String.join(";", headers.keySet());

        String canonicalRequest = method + "\n"
                + uri + "\n"
                + query + "\n"
                + canonicalHeaders + "\n"
                + signedHeaders + "\n"
                + payloadHash;

        String scope = dateStamp + "/" + region + "/" + SERVICE + "/aws4_request";
        String stringToSign = ALGORITHM + "\n" + amzDate + "\n" + scope + "\n"
                + hex(sha256(canonicalRequest.getBytes(StandardCharsets.UTF_8)));

        byte[] kDate = hmac(("AWS4" + secretKey).getBytes(StandardCharsets.UTF_8), dateStamp);
        byte[] kRegion = hmac(kDate, region);
        byte[] kService = hmac(kRegion, SERVICE);
        byte[] kSigning = hmac(kService, "aws4_request");
        String signature = hex(hmac(kSigning, stringToSign));

        Map<String, String> out = new LinkedHashMap<>();
        out.put("Authorization", ALGORITHM + " Credential=" + accessKey + "/" + scope
                + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature);
        out.put("x-amz-date", amzDate);
        out.put("x-amz-content-sha256", payloadHash);
        if (!token.isEmpty()) {
            out.put("x-amz-security-token", token);
        }
        return new Signed(canonicalRequest, scope, out);
    }

    /**
     * URI-encodes an (unencoded) object path for S3: every segment is encoded exactly once,
     * '/' is kept. Use the SAME encoded string for signing and for the request path.
     */
    public static String encodePath(String path) {
        if (path == null || path.isEmpty()) {
            return "/";
        }
        String[] segments = path.split("/", -1);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < segments.length; i++) {
            if (i > 0) {
                sb.append('/');
            }
            sb.append(uriEncode(segments[i]));
        }
        String encoded = sb.toString();
        return encoded.startsWith("/") ? encoded : "/" + encoded;
    }

    /** Builds a canonical query string (encoded, sorted by key) from raw parameters. */
    public static String canonicalQueryString(Map<String, String> params) {
        if (params == null || params.isEmpty()) {
            return "";
        }
        TreeMap<String, String> sorted = new TreeMap<>();
        for (Map.Entry<String, String> e : params.entrySet()) {
            sorted.put(uriEncode(e.getKey()), uriEncode(e.getValue() == null ? "" : e.getValue()));
        }
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : sorted.entrySet()) {
            if (sb.length() > 0) {
                sb.append('&');
            }
            sb.append(e.getKey()).append('=').append(e.getValue());
        }
        return sb.toString();
    }

    // RFC 3986 unreserved characters are left alone, everything else is %XX (upper-case hex)
    static String uriEncode(String s) {
        StringBuilder sb = new StringBuilder();
        for (byte b : s.getBytes(StandardCharsets.UTF_8)) {
            char c = (char) (b & 0xff);
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_' || c == '.' || c == '~') {
                sb.append(c);
            } else {
                sb.append('%').append(Character.toUpperCase(Character.forDigit((b >> 4) & 0xf, 16)))
                        .append(Character.toUpperCase(Character.forDigit(b & 0xf, 16)));
            }
        }
        return sb.toString();
    }

    private static String normalizeHeaderValue(String v) {
        return v.trim().replaceAll("\\s+", " ");
    }

    private static String required(Map<String, Object> req, String key) {
        Object v = req.get(key);
        if (v == null || String.valueOf(v).isEmpty()) {
            throw new IllegalArgumentException("Missing required signing parameter: " + key);
        }
        return String.valueOf(v);
    }

    private static String optional(Map<String, Object> req, String key) {
        Object v = req.get(key);
        return v == null ? "" : String.valueOf(v);
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] hmac(byte[] key, String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String hex(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            out[i * 2] = HEX[(bytes[i] >> 4) & 0xf];
            out[i * 2 + 1] = HEX[bytes[i] & 0xf];
        }
        return new String(out);
    }
}
