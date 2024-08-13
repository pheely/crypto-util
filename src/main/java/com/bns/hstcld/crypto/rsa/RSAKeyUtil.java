package com.bns.hstcld.crypto.rsa;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSAKeyUtil {
  public static String convertPkcs1ToPkcs8(String pkcs1) {
    var pem = pkcs1.replaceAll("-----.+KEY-----", "")
        .replaceAll("\\s+", "");
    var bytes = Base64.getDecoder().decode(pem);

    var pkcs8Bytes = new byte[bytes.length + 26];
    System.arraycopy(Base64.getDecoder().decode(
        "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKY="), 0, pkcs8Bytes, 0, 26);
    System.arraycopy(BigInteger.valueOf(pkcs8Bytes.length - 4).toByteArray(), 0, pkcs8Bytes, 2, 2);
    System.arraycopy(BigInteger.valueOf(bytes.length).toByteArray(), 0, pkcs8Bytes, 24, 2);
    System.arraycopy(bytes, 0, pkcs8Bytes, 26, bytes.length);

    return new String(Base64.getEncoder().encode(pkcs8Bytes));
  }

  public static RSAPrivateCrtKey getTraditionalPrivateKeyFromdPKCS8(String pkcs8)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    RSAPrivateKey privateKey = readPKCS8PrivateKey(pkcs8);
    RSAPrivateCrtKey privateCrtKey = (RSAPrivateCrtKey) privateKey;
    return privateCrtKey;
  }
  public static RSAPrivateKey readPKCS8PrivateKey(String pkcs8Pem)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    var pem = pkcs8Pem.replaceAll("-----.+KEY-----", "")
        .replaceAll("\\s+", "");
    var bytes = Base64.getDecoder().decode(pem);

    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);

    RSAPrivateKey privateKey =
        (RSAPrivateKey) keyFactory.generatePrivate(keySpec);

    return privateKey;
  }

  public static X509Certificate readX509Certificate(String certificatePem)
      throws CertificateException {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(
        new ByteArrayInputStream(certificatePem.getBytes()));
    return certificate;
  }

  public static RSAPublicKey readPKCS8PublicKey(String publicKeyPem)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    var pem = publicKeyPem.replaceAll("-----.+KEY-----", "")
        .replaceAll("\\s+", "");
    var bytes = Base64.getDecoder().decode(pem);

    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    X509EncodedKeySpec publicKeySpec =
        new X509EncodedKeySpec(bytes);
    RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);

    return publicKey;
  }

  public static RSAPublicKey getPublicKeyFromPrivateKey(RSAPrivateKey privateKey)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    RSAPrivateCrtKey privateCrtKey = (RSAPrivateCrtKey) privateKey;
    RSAPublicKeySpec publicKeySpec =
        new RSAPublicKeySpec(privateCrtKey.getModulus(), privateCrtKey.getPublicExponent());
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);

    return publicKey;
  }
}
