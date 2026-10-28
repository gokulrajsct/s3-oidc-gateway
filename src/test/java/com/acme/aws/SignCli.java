package com.acme.aws;
import java.io.*; import java.time.*; import java.util.*;
/** stdin: one request per line, tab separated: method host rawKey pathPrefix region payloadHash ak sk token epochSec
 *  stdout: encodedPath \t header=value \t header=value ... */
public class SignCli {
  public static void main(String[] a) throws Exception {
    BufferedReader r = new BufferedReader(new InputStreamReader(System.in, "UTF-8"));
    PrintStream out = new PrintStream(System.out, true, "UTF-8");
    for (String line; (line = r.readLine()) != null; ) {
      String[] f = line.split("\t", -1);
      String encodedPath = S3SigV4Signer.encodePath(f[3] + "/" + f[2]);   // same expression as the Mule flow
      Map<String,Object> req = new HashMap<>();
      req.put("method", f[0]); req.put("host", f[1]); req.put("uri", encodedPath); req.put("query", "");
      req.put("region", f[4]); req.put("payloadHash", f[5]); req.put("accessKeyId", f[6]);
      req.put("secretAccessKey", f[7]); req.put("sessionToken", f[8]); req.put("headers", new HashMap<>());
      Map<String,String> h = S3SigV4Signer.signAt(req, Clock.fixed(Instant.ofEpochSecond(Long.parseLong(f[9])), ZoneOffset.UTC));
      StringBuilder sb = new StringBuilder(encodedPath);
      for (Map.Entry<String,String> e : h.entrySet()) sb.append('\t').append(e.getKey()).append('=').append(e.getValue());
      out.println(sb);
    }
  }
}
