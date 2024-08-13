package com.bns.hstcld.crypto.rsa;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class CipherUtil {

  public static String rsaEncrypt(String data, X509Certificate certificate)
      throws NoSuchPaddingException, IllegalBlockSizeException,
      NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
    RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();
    return CipherUtil.rsaEncrypt(data, publicKey);
  }

  public static String rsaEncrypt(String data, RSAPublicKey publicKey)
      throws NoSuchPaddingException, NoSuchAlgorithmException,
      InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    // see https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html
    // for all supported standards
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    byte[] ciphertext = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

    return Base64.getEncoder().encodeToString(ciphertext);
  }

  public static String rsaDecrypt(String ciphertextString, RSAPrivateKey privateKey)
      throws NoSuchPaddingException, NoSuchAlgorithmException,
      InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    cipher.init(Cipher.DECRYPT_MODE, privateKey);
    byte[] cipphertext = Base64.getDecoder().decode(ciphertextString);
    byte[] plaintext = cipher.doFinal(cipphertext);

    return new String(plaintext);
  }
}
