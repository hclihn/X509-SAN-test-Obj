import x509 from './x509.js';

const cert = `-----BEGIN CERTIFICATE-----
    MIIIlTCCCDygAwIBAgIQZNV05YqnQ6CgPBtNhzfNvzAKBggqhkjOPQQDAjCBhDEr
    MCkGCgmSJomT8ixkAQEMG2lkZW50aXR5OmlkbXMuZ3JvdXAuNTUwNDQ4NzEtMCsG
    A1UEAwwkYXBwYXV0aG9yaXR5MDAzLmNuZ3lhMDUucGllLnNpbHUubmV0MSYwJAYD
    VQQLDB1tYW5hZ2VtZW50OmlkbXMuZ3JvdXAuMTQwNTIwNjAeFw0yNDA2MjYyMDM3
    NTVaFw0yNDA3MDYyMDQyNTVaMIH0MQswCQYDVQQGEwJVUzEnMCUGA1UECwwebWFu
    YWdlbWVudDppZG1zLmdyb3VwLjEwODYyNzA0MRMwEQYDVQQLDApjbi1lYXN0LTFl
    MS0wKwYDVQQDDCRlOWQyNTE4My03ZmJhLTQxMDQtOTE0ZS1iZWFmYWU2ZTcyMGIx
    LDAqBgoJkiaJk/IsZAEBDBxpZGVudGl0eTppZG1zLmdyb3VwLjExMTMzMTg0MSEw
    HwYDVQQLDBhvd25lcjppZG1zLmdyb3VwLjU1NDgzMTYxJzAlBgNVBAoMHm1hbmFn
    ZW1lbnQ6aWRtcy5ncm91cC4xMDg2MjcwNDBZMBMGByqGSM49AgEGCCqGSM49AwEH
    A0IABF9SXaxFQWFUceajrIpwTR58E5WEXE2EGI2oYM4O/OcIXY/ohW8Et3rZmyBt
    SxTbpVxzw0mIaUkrnu4tECNLBIqjggYcMIIGGDCCA3UGA1UdEQSCA2wwggNogjZj
    YWJvb2RsZS1nYXRla2VlcGVyLWdjYmQuY2Fib29kbGUtZ2F0ZWtlZXBlci1nY2Jk
    Lmt1YmWCRyouY2Fib29kbGUtZ2F0ZWtlZXBlci1nY2JkLmNhYm9vZGxlLWdhdGVr
    ZWVwZXItZ2NiZC5rdWJlLmNsb3VkLnNpbHUubmV0hntmbHVmZnk6Ly9jYWJvb2Rs
    ZS1nYXRla2VlcGVyLWdjYmQuY2Fib29kbGUtZ2F0ZWtlZXBlci1nY2JkLmt1YmUu
    MTQwNTIwNi9vd25lcj01NTQ4MzE2L21hbmFnZW1lbnQ9MTA4NjI3MDQvaWRlbnRp
    dHk9MTExMzMxODSHBKwVE1SHECQC8UAQEAG7AAAAAAAAAA2HBKwVE1SHBKwQsuuH
    ECQC8UAQKjsNAAAAAAAAABWHBKwWtgiCVGNhYm9vZGxlLWdhdGVrZWVwZXItZ2Ni
    ZC5jYWJvb2RsZS1nYXRla2VlcGVyLWdjYmQua3ViZS5jbi1lYXN0LTFlLms4cy5j
    bG91ZC5zaWx1Lm5ldII9Y2Fib29kbGUtZ2F0ZWtlZXBlci1zZXJ2aWNlLWdjYmQu
    Y2Fib29kbGUtZ2F0ZWtlZXBlci1nY2JkLnN2Y4JgY2Fib29kbGUtZ2F0ZWtlZXBl
    ci1zZXJ2aWNlLWdjYmQuY2Fib29kbGUtZ2F0ZWtlZXBlci1nY2JkLnN2Yy5rdWJl
    LmNuLWVhc3QtMWUuazhzLmNsb3VkLnNpbHUubmV0gmIqLmNhYm9vZGxlLWdhdGVr
    ZWVwZXItc2VydmljZS1nY2JkLmNhYm9vZGxlLWdhdGVrZWVwZXItZ2NiZC5zdmMu
    a3ViZS5jbi1lYXN0LTFlLms4cy5jbG91ZC5zaWx1Lm5ldIJ5Y2Fib29kbGUtZ2F0
    ZWtlZXBlci1nY2JkLmNhYm9vZGxlLWdhdGVrZWVwZXItc2VydmljZS1nY2JkLmNh
    Ym9vZGxlLWdhdGVrZWVwZXItZ2NiZC5zdmMua3ViZS5jbi1lYXN0LTFlLms4cy5j
    bG91ZC5zaWx1Lm5ldIJWY2Fib29kbGUtZ2F0ZWtlZXBlci1nY2JkLmNhYm9vZGxl
    LWdhdGVrZWVwZXItc2VydmljZS1nY2JkLmNhYm9vZGxlLWdhdGVrZWVwZXItZ2Ni
    ZC5zdmMwggGPBgkrBgEEAT+FZwEEggGABIIBfAo2Y2Fib29kbGUtZ2F0ZWtlZXBl
    ci1nY2JkLmNhYm9vZGxlLWdhdGVrZWVwZXItZ2NiZC5rdWJlEgpjbi1lYXN0LTFl
    GrMBCAAQABgAIAAoADAAOABAAEokCgpjbi1lYXN0LTFlEhRwbGIucGllLXBsYi5w
    aWUtcHJvZBgASiQKCmNuLWVhc3QtMWUSFGtub2RlMTEwMy5jbmd5YTA1LmtrGAFi
    GBIULmNhYm9vZGxlLXByb3h5Lmt1YmUYAGoWUElFIFZJUCAmIEJHUCBOZXR3b3Jr
    c3gAgAEAigEdCgNTRFISFlBJRSBWSVAgJiBCR1AgTmV0d29ya3MiCAgAEAAYADAA
    MjZjYWJvb2RsZS1nYXRla2VlcGVyLWdjYmQuY2Fib29kbGUtZ2F0ZWtlZXBlci1n
    Y2JkLmt1YmUyPmNhYm9vZGxlLWdhdGVrZWVwZXItc2VydmljZS1nY2JkLmNhYm9v
    ZGxlLWdhdGVrZWVwZXItZ2NiZC5rdWJlMC8GCSsGAQQBP4VnAwQiBCBlbnRpdGxl
    bWVudHMucHJvZHVjdGlvbi5wbGF0Zm9ybTAmBgkrBgEEAT+FZwIEGQQXc2NoZWR1
    bGVzaWduZXIua3ViZS5waWUwGQYJKwYBBAE/hWcIBAwECmNuLWVhc3QtMWUwGQYJ
    KwYBBAE/hWcJBAwMCmNuLWVhc3QtMWUwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8E
    BAMCA6gwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMB0GA1UdDgQWBBT9
    QItwibra8NPsSPOEMsH2q3F8bDAfBgNVHSMEGDAWgBT1K6k7nOehy/7bi1LBgkSa
    0mKO4TAKBggqhkjOPQQDAgNHADBEAiAa3Kw/nrtHUT25PxyN/vs8LN3yiLH58LYK
    B9GDH31aswIgWEMyygX+CfbsGOx/7zowCvbSjbkZ/6srH9Xp7qyXYZw=
    -----END CERTIFICATE-----
`;


/**
 * Get subjectAltName (SAN) from X.509 PEM certificate.
 * @param  {string} pem_cert - The PEM string to be parsed.
 * @return {string[]} The array of SANs.
 */
function san(pem_cert /*r*/) {
    //var pem_cert = r.variables.ssl_client_raw_cert;
    if (!pem_cert) {
        return '{"error": "no client certificate"}'; //??
    }

    var cert = x509.parse_pem_cert(pem_cert);
    console.log(JSON.stringify(cert, null, 2));
    // subjectAltName oid 2.5.29.17
    // return JSON.stringify(x509.get_oid_value(cert, "2.5.29.17")[0]);
    return x509.get_oid_value(cert, "2.5.29.17")[0];
}

try {
  var s = 'SANs:\n';
  var sans = san(cert);
  for (var i = 0; i<sans.length; i++) {
      s += sans[i] + '\n';
  } 
  console.log(s);
} catch(err) {
  console.log(err);
}
