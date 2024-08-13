package com.bns.hstcld.crypto.main;

import com.bns.hstcld.crypto.rsa.CipherUtil;
import com.bns.hstcld.crypto.rsa.RSAKeyUtil;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Application implements CommandLineRunner {
  private final Logger logger = LoggerFactory.getLogger(Application.class);

  public static void main(String[] args) {
    SpringApplication.run(Application.class, args);
  }

  public void run(String... args) throws Exception {
//    testRSAFormatConversion();
//    testReadPrivateKey();
//    testReadCertificate();
//    testReadPublicKey();
//    testGetPublicKeyFromPrivateKey();
    testRsaEncryptionDecryption();
  }

  private void testRsaEncryptionDecryption() throws Exception {
    String plaintext = "PlJ";
    logger.info("plaintext: {}", plaintext);
    RSAPublicKey publicKey= testGetPublicKeyFromPrivateKey();

    String ciphertext = CipherUtil.rsaEncrypt(plaintext, publicKey);
    logger.info("ciphertext: {}", ciphertext);

    String decrypted = CipherUtil.rsaDecrypt(ciphertext, testReadPrivateKey());
    logger.info("decrypted: {}", decrypted);
  }

  private RSAPublicKey testGetPublicKeyFromPrivateKey() throws Exception {
    RSAPrivateKey privateKey = testReadPrivateKey();
    RSAPublicKey publicKey = RSAKeyUtil.getPublicKeyFromPrivateKey(privateKey);
    return publicKey;
  }

  private void testReadPublicKey() throws Exception {
    var publicKeyPem = """
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuQYYpHdLAB/1oIAcrGt5
        JFMxvlL2k/NHqsEw0psPfjz01jUBikM+2aYXA1Mgt+AeTWcKZUMdRCmgo795E/yC
        oWz3EI637itI4xm39r3Ki8RYncKfW7gJMBLBjywLIsj8Kocn4sck6/J/Wl+Sw6fR
        lBv3p1ooMoN9FiqpAB52hhaY8oug3ZjkvX5xWaLOaMFn7v2Pb9d+xWUVqvmHUhW2
        /vN5tIfz0EM9XKaeJIJ87H1ycHO6QYKfd7xA18tltdt0oLLJH2MPxkdrB8JAt+jw
        kzjh+/4uH0PNORuAcQoDtcLHJgcW7tYcDdHdArZXXZztnVnZ7BIOR3bpoNer6pOB
        HwIDAQAB
        -----END PUBLIC KEY-----
        """;
    logger.info(RSAKeyUtil.readPKCS8PublicKey(publicKeyPem).toString());
  }

  private X509Certificate testReadCertificate() throws Exception {
    String certPem = """
        -----BEGIN CERTIFICATE-----
        MIIE0DCCA7igAwIBAgIEY8grnzANBgkqhkiG9w0BAQsFADAiMQswCQYDVQQGEwJD
        QTETMBEGA1UEChMKU2NvdGlhYmFuazAeFw0yNDAyMjgxODAxNDdaFw0yNjAyMjgx
        ODMxNDdaMG0xCzAJBgNVBAYTAkNBMRMwEQYDVQQKEwpTY290aWFiYW5rMQwwCgYD
        VQQLEwNCTUExHDAaBgNVBAsTE0NyeXB0byBDZXJ0aWZpY2F0ZXMxHTAbBgNVBAMT
        FGJmYzgtY2xlLWNtay1pc3QuYm5zMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
        CgKCAQEA1IXSYjhiiMlB9ywG/oPhUhG9cOQ87HysZ8beZN+jBcpt1mH5WV2pdbbF
        pjK8q9Gu3/xKxyRyh2ZkZFKq4uHTJrGtVPSN1Q6KdmgHcva7uGAXglHawrWdspOj
        yYZ/BxVgRhA5/Ht5pLqgdjG/y9YVdVQ374JeF+MXv5GvQVsHr4H7QJ9A6kmMl+77
        lKYeIjdvWqzjT8tNAFgtmxR/NFBiNF4Kw6tOUiAH6z7//z/1AzEjIAvmyzW3NLw4
        XEMEnUPaFWK5CeISarzfhTij6mVK0gVfvVt4VzVTyNf2D56P1LtkYIGsWmcR2sIc
        YJ+MKBBddYofgWkKQ6ymyxXx9MuJUQIDAQABo4IBwTCCAb0wHwYDVR0RBBgwFoIU
        YmZjOC1jbGUtY21rLWlzdC5ibnMwCwYDVR0PBAQDAgWgMHkGCCsGAQUFBwEBBG0w
        azAtBggrBgEFBQcwAYYhSFRUUDovL29jc3AuZXBraS5nbGIubWZhLmJuczoyNTYw
        MDoGCCsGAQUFBzAChi5odHRwOi8vY2VydHJzLmVwa2kuZ2xiLm1mYS5ibnMvZVBL
        SV9DQUNlcnQuY2VyMH8GA1UdHwR4MHYwPKA6oDikNjA0MQswCQYDVQQGEwJDQTET
        MBEGA1UEChMKU2NvdGlhYmFuazEQMA4GA1UEAxMHQ1JMMTE5ODA2oDSgMoYwaHR0
        cDovL2NlcnRycy5lcGtpLmdsYi5tZmEuYm5zL2NvbWJpbmVkX2Vwa2kuY3JsMCsG
        A1UdEAQkMCKADzIwMjQwMjI4MTgwMTQ3WoEPMjAyNjAyMjgxODMxNDdaMB8GA1Ud
        IwQYMBaAFNIGgDzFSXrsZxlhqRFCeU8ol+I7MB0GA1UdDgQWBBSUMaxVfRyb9fSS
        nC9OWk0DA0hUnzAJBgNVHRMEAjAAMBkGCSqGSIb2fQdBAAQMMAobBFY4LjMDAgSw
        MA0GCSqGSIb3DQEBCwUAA4IBAQCH3lRvxZDgKRu7UQNs/Iphk2li9igqx+3uTUOS
        nqR31u/9FhG1JiBMqVao+JvuGixpUXBQZDAwQ/QIOX2KO38Y9hYn/az8TuK8vt+0
        afcnZGTihIlqQOl/RhRLoaBoMkyJnTz8jFL4F/t5EO63rIIExROWD2wxA5JUHILn
        valMe5o1AS8vzw1xHeQJ5qgErfHB7gf+Ay9hxWTPkY5fRsuqRzlGBrvoYuM/fSA2
        X/wiUXKV6p/pFqD3tnfVPsUGMe30y32YM8nqkCtABOPUh6UtFUypnsuRAMxoBBfO
        Yyj2fAeM1eH7k4t6rzAv3PJXb8Gl9Yj5+0XhyBsV9JANtBoo
        -----END CERTIFICATE-----
        """;
    return RSAKeyUtil.readX509Certificate(certPem);
  }

  private RSAPrivateKey testReadPrivateKey() throws Exception {
    String pkcs8Pem = """
        -----BEGIN PRIVATE KEY-----
        MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC5Bhikd0sAH/Wg
        gBysa3kkUzG+UvaT80eqwTDSmw9+PPTWNQGKQz7ZphcDUyC34B5NZwplQx1EKaCj
        v3kT/IKhbPcQjrfuK0jjGbf2vcqLxFidwp9buAkwEsGPLAsiyPwqhyfixyTr8n9a
        X5LDp9GUG/enWigyg30WKqkAHnaGFpjyi6DdmOS9fnFZos5owWfu/Y9v137FZRWq
        +YdSFbb+83m0h/PQQz1cpp4kgnzsfXJwc7pBgp93vEDXy2W123SgsskfYw/GR2sH
        wkC36PCTOOH7/i4fQ805G4BxCgO1wscmBxbu1hwN0d0CtlddnO2dWdnsEg5Hdumg
        16vqk4EfAgMBAAECggEAFg+3sSdBkR0+cMnLIXVFzOKtRA/+XhEcUtbq7GHCzNRA
        g/4ZVeluErjuy4hblrEpdnnlJRfbOH0Xg2Qu8AbOyKgGeY9FjSd/bwdqW7MGS04O
        cZkliTkowfZVOq4PZzFnJ+b/sYGkpww+H9d/ghwo2CvRhr8wRdL51O0h7jqzpTR+
        WFiOKvw9q1fxVx/m5DnxF9nV8kOkO4fawzD9BEs1dpHlKdbhdEQyx9iVZ/vajZOD
        TaLRTcG7aiQSMt7pP4dSaimbtJiFWHCegkVp1Q+i1uC+Q4vgvD7zN8/qfjdzZ8+a
        t/Z1hoImn+Rn1mhM3/C7OWH7ha7DYg1vIf74x5eJiQKBgQDzm9QdkFEcRxzUDIj1
        RLoE7PB6PxGWF8tXM+OtDST1wHbt3oRhMj9dkzdl1QhELWCzIQhEsZQCuxXszpt9
        RBkGNjzPFpuj0xjA2NjiW7d3GKASl09mrjm0wRREK+iu4ogKmiNE6/NInavI48Xy
        n21Cgq1qlGgZ2RpypaMpPswn8wKBgQDCb2ZIgx0x7nXnSF1YR4C4cVnj+Gf1OD1G
        HPsXbzoDzzLrs4x1IM5BQhyL6Dgl+42LhbBP/TrwK7D22HrZSKYCFV7ij3A0aVxd
        +bYd/g664mf7ULzsG3JxnhHLzK7sQazP+gCfXWnTqn5uXBvj1YkOEcGJIsHu5pCU
        klM0CekZJQKBgQDoy600Y0lfoIVoDmKDIB4zvsk/yS1hJXPn7WpRYRJE1pvQTKhs
        ybvMDHcQFThFDqguBg8Etj4fLfGRzw6/8meHjCUoMQ6iy4QIJjF8fvEgGqQ9n+L8
        2NnEZg6b5uoA1fHzT8EMh/6BEkurOh9b8AZVXNOj2hZxPQsNLERzkdM/CQKBgGTS
        33c6hikePoVwQPdGHLmIDdTpOv8t6pgw7wN36d2P1BflQzB5knrEjYj/Ih6QExYG
        fSb9aVKhVWKrXwjNY0gxTMKvHsAO4pbYpldnJrxCKylm9JB6qx2/mfrUaOCaLcKr
        ISeCiR35ixYvLUc3s5pYGsPCAk6fwNlKB1s0yGsBAoGBAIXULpk7qgwrS5UK9XSM
        g8MYdP4Ezfzf3HHxyLJLgNJY96fVgW/P6kPa9N7vbycuABf/0c1VUi7bdt4LIVNW
        AudfRIGUeaNl26NVHPHZ3khFzq6cKreYi+yJRGUDpA7jr7riBHU2D028f3t8sBoq
        j96iLBW3PTZlTXpCLOwo4FiH
        -----END PRIVATE KEY-----
        """;
    return RSAKeyUtil.readPKCS8PrivateKey(pkcs8Pem);
  }

  private void testRSAFormatConversion() {
    String pkcs1Pem = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEAuQYYpHdLAB/1oIAcrGt5JFMxvlL2k/NHqsEw0psPfjz01jUB
        ikM+2aYXA1Mgt+AeTWcKZUMdRCmgo795E/yCoWz3EI637itI4xm39r3Ki8RYncKf
        W7gJMBLBjywLIsj8Kocn4sck6/J/Wl+Sw6fRlBv3p1ooMoN9FiqpAB52hhaY8oug
        3ZjkvX5xWaLOaMFn7v2Pb9d+xWUVqvmHUhW2/vN5tIfz0EM9XKaeJIJ87H1ycHO6
        QYKfd7xA18tltdt0oLLJH2MPxkdrB8JAt+jwkzjh+/4uH0PNORuAcQoDtcLHJgcW
        7tYcDdHdArZXXZztnVnZ7BIOR3bpoNer6pOBHwIDAQABAoIBABYPt7EnQZEdPnDJ
        yyF1RczirUQP/l4RHFLW6uxhwszUQIP+GVXpbhK47suIW5axKXZ55SUX2zh9F4Nk
        LvAGzsioBnmPRY0nf28HaluzBktODnGZJYk5KMH2VTquD2cxZyfm/7GBpKcMPh/X
        f4IcKNgr0Ya/MEXS+dTtIe46s6U0flhYjir8PatX8Vcf5uQ58RfZ1fJDpDuH2sMw
        /QRLNXaR5SnW4XREMsfYlWf72o2Tg02i0U3Bu2okEjLe6T+HUmopm7SYhVhwnoJF
        adUPotbgvkOL4Lw+8zfP6n43c2fPmrf2dYaCJp/kZ9ZoTN/wuzlh+4Wuw2INbyH+
        +MeXiYkCgYEA85vUHZBRHEcc1AyI9US6BOzwej8RlhfLVzPjrQ0k9cB27d6EYTI/
        XZM3ZdUIRC1gsyEIRLGUArsV7M6bfUQZBjY8zxabo9MYwNjY4lu3dxigEpdPZq45
        tMEURCvoruKICpojROvzSJ2ryOPF8p9tQoKtapRoGdkacqWjKT7MJ/MCgYEAwm9m
        SIMdMe5150hdWEeAuHFZ4/hn9Tg9Rhz7F286A88y67OMdSDOQUIci+g4JfuNi4Ww
        T/068Cuw9th62UimAhVe4o9wNGlcXfm2Hf4OuuJn+1C87BtycZ4Ry8yu7EGsz/oA
        n11p06p+blwb49WJDhHBiSLB7uaQlJJTNAnpGSUCgYEA6MutNGNJX6CFaA5igyAe
        M77JP8ktYSVz5+1qUWESRNab0EyobMm7zAx3EBU4RQ6oLgYPBLY+Hy3xkc8Ov/Jn
        h4wlKDEOosuECCYxfH7xIBqkPZ/i/NjZxGYOm+bqANXx80/BDIf+gRJLqzofW/AG
        VVzTo9oWcT0LDSxEc5HTPwkCgYBk0t93OoYpHj6FcED3Rhy5iA3U6Tr/LeqYMO8D
        d+ndj9QX5UMweZJ6xI2I/yIekBMWBn0m/WlSoVViq18IzWNIMUzCrx7ADuKW2KZX
        Zya8QispZvSQeqsdv5n61Gjgmi3CqyEngokd+YsWLy1HN7OaWBrDwgJOn8DZSgdb
        NMhrAQKBgQCF1C6ZO6oMK0uVCvV0jIPDGHT+BM3839xx8ciyS4DSWPen1YFvz+pD
        2vTe728nLgAX/9HNVVIu23beCyFTVgLnX0SBlHmjZdujVRzx2d5IRc6unCq3mIvs
        iURlA6QO46+64gR1Ng9NvH97fLAaKo/eoiwVtz02ZU16QizsKOBYhw==
        -----END RSA PRIVATE KEY-----
        """;
    logger.info(RSAKeyUtil.convertPkcs1ToPkcs8(pkcs1Pem));
  }
}
