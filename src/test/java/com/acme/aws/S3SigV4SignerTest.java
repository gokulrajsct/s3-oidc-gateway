package com.acme.aws;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Checks the signer against the worked examples in the AWS documentation
 * ("Signature Calculations for the Authorization Header", S3, 24 May 2013).
 */
class S3SigV4SignerTest {

    private static final Clock FIXED = Clock.fixed(Instant.parse("2013-05-24T00:00:00Z"), ZoneOffset.UTC);
    private static final String EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    private static Map<String, Object> base(String method, String uri, String payloadHash) {
        Map<String, Object> req = new HashMap<>();
        req.put("method", method);
        req.put("host", "examplebucket.s3.amazonaws.com");
        req.put("uri", uri);
        req.put("query", "");
        req.put("region", "us-east-1");
        req.put("payloadHash", payloadHash);
        req.put("accessKeyId", "AKIAIOSFODNN7EXAMPLE");
        req.put("secretAccessKey", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        return req;
    }

    private static String signatureOf(Map<String, String> headers) {
        String auth = headers.get("Authorization");
        return auth.substring(auth.indexOf("Signature=") + "Signature=".length());
    }

    @Test
    void getObjectWithRangeHeader() {
        Map<String, Object> req = base("GET", "/test.txt", EMPTY_SHA256);
        Map<String, String> extra = new HashMap<>();
        extra.put("Range", "bytes=0-9");
        req.put("headers", extra);

        Map<String, String> out = S3SigV4Signer.signAt(req, FIXED);

        assertEquals("f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41", signatureOf(out));
        assertTrue(out.get("Authorization").contains("SignedHeaders=host;range;x-amz-content-sha256;x-amz-date"));
        assertFalse(out.containsKey("x-amz-security-token"));
    }

    @Test
    void putObjectWithStorageClassAndEncodedKey() {
        Map<String, Object> req = base("PUT", S3SigV4Signer.encodePath("/test$file.text"),
                "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072");
        Map<String, String> extra = new HashMap<>();
        extra.put("date", "Fri, 24 May 2013 00:00:00 GMT");
        extra.put("x-amz-storage-class", "REDUCED_REDUNDANCY");
        req.put("headers", extra);

        Map<String, String> out = S3SigV4Signer.signAt(req, FIXED);

        assertEquals("98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd", signatureOf(out));
    }

    @Test
    void getBucketLifecycleWithQueryString() {
        Map<String, Object> req = base("GET", "/", EMPTY_SHA256);
        req.put("query", S3SigV4Signer.canonicalQueryString(Map.of("lifecycle", "")));

        Map<String, String> out = S3SigV4Signer.signAt(req, FIXED);

        assertEquals("fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543", signatureOf(out));
    }

    @Test
    void sessionTokenIsSignedAndReturned() {
        Map<String, Object> req = base("GET", "/test.txt", EMPTY_SHA256);
        req.put("sessionToken", "FwoGZXIvYXdzEXAMPLETOKEN");

        Map<String, String> out = S3SigV4Signer.signAt(req, FIXED);

        assertEquals("FwoGZXIvYXdzEXAMPLETOKEN", out.get("x-amz-security-token"));
        assertTrue(out.get("Authorization")
                .contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token"));
    }

    @Test
    void encodePathEncodesEachSegmentOnceAndKeepsSlashes() {
        assertEquals("/", S3SigV4Signer.encodePath(""));
        assertEquals("/folder/my%20file%2B1.pdf", S3SigV4Signer.encodePath("/folder/my file+1.pdf"));
        assertEquals("/folder/file.pdf", S3SigV4Signer.encodePath("folder/file.pdf"));
        assertEquals("/%C3%A9.txt", S3SigV4Signer.encodePath("/é.txt"));
    }

    @Test
    void describeShowsCanonicalRequestAndMasksTheToken() {
        Map<String, Object> req = base("PUT", "/data/order-55.json", EMPTY_SHA256);
        req.put("sessionToken", "SECRET-SESSION-TOKEN");

        String described = S3SigV4Signer.describeAt(req, FIXED);

        assertTrue(described.startsWith("PUT\n/data/order-55.json\n\nhost:examplebucket.s3.amazonaws.com\n"));
        assertTrue(described.contains("x-amz-security-token:<masked>"));
        assertFalse(described.contains("SECRET-SESSION-TOKEN"));
        assertTrue(described.contains("--- credential scope: 20130524/us-east-1/s3/aws4_request"));
    }

    @Test
    void missingRequiredParameterIsRejected() {
        Map<String, Object> req = base("GET", "/test.txt", EMPTY_SHA256);
        req.remove("secretAccessKey");
        assertThrows(IllegalArgumentException.class, () -> S3SigV4Signer.signAt(req, FIXED));
    }
}
