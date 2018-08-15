package com.diebold.encryption.rsa;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.bc.BcPEMDecryptorProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import javax.crypto.Cipher;
import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;


/**
 *
 * https://connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-rsa-encryption
 *
 * Openssl
 * https://www.openssl.org/source/
 * https://rietta.com/blog/2012/01/27/openssl-generating-rsa-key-from-command/
 *
 * # Private Key - voce pode adicionar uma senha pra criptrogravar a geracao do certificado .
 * openssl genrsa -des3 -out private.pem 2048
 *
 * # Private Key - Gera o certificado sem precisar passar senha
 * openssl genrsa -out servcore-private.pem 2048
 *
 * # Public key.
 * openssl rsa -in private.pem -outform PEM -pubout -out public.pem
 *
 */
public class MimbusJoseJwtTest {

    public static final String PASSWORD = "660992";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    static String accessToken(KeyPair keyPair) throws JOSEException {
        Date now = new Date();

        // Prepare JWT with claims set
        JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                .subject("DigitalAccount")
                .issuer("https://c2id.com")
                .claim("android_version", "1.0.1")
                .claim("ios_version", "2.0.0")
                .expirationTime(new Date(now.getTime() + 1000*60*10)) // expires in 10 minutes
                //.expirationTime(new Date(now.getTime() + 1000*30)) // expires in 30 seconds
                .notBeforeTime(now)
                .issueTime(now)
                .jwtID(UUID.randomUUID().toString())
                .build();

        System.out.println(jwtClaims.toJSONObject());

        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256CBC_HS512);
        EncryptedJWT jwt = new EncryptedJWT(header, jwtClaims);
        RSAEncrypter encrypter = new RSAEncrypter((RSAPublicKey) keyPair.getPublic());
        jwt.encrypt(encrypter);
        return jwt.serialize();
    }

    static boolean validateAccessToken(KeyPair keyPair, String accessToken) {
        try {
            EncryptedJWT encrypted = EncryptedJWT.parse(accessToken);
            RSADecrypter decrypter = new RSADecrypter(keyPair.getPrivate());
            encrypted.decrypt(decrypter);
            JWTClaimsSet jwtClaims = encrypted.getJWTClaimsSet();
            System.out.println(jwtClaims.toJSONObject());
            Date now = new Date();
            Date exp = jwtClaims.getExpirationTime();
            if (now.after(exp)) {
                throw new RuntimeException("Token expired");
            }
        } catch (ParseException | JOSEException e) {
            e.printStackTrace();
            return Boolean.FALSE;
        }
        return Boolean.TRUE;

    }

    public static KeyPair readPrivateKey(Reader privateKeyReader) throws IOException {
        try (PEMParser pemParser = new PEMParser(privateKeyReader)) {
            Object obj = pemParser.readObject();
            PEMKeyPair pemKeyPair = null;
            if (obj instanceof PEMKeyPair) {
                pemKeyPair = (PEMKeyPair) obj;
            } else if (obj instanceof PEMEncryptedKeyPair) {
                PEMEncryptedKeyPair encryptedKeyPair = (PEMEncryptedKeyPair) obj;
                pemKeyPair = encryptedKeyPair.decryptKeyPair(new BcPEMDecryptorProvider(PASSWORD.toCharArray()));
            }

            return new JcaPEMKeyConverter().setProvider("BC").getKeyPair(pemKeyPair);
        }
    }


    public static String encrypt(Key key, String text) throws IOException, GeneralSecurityException {
        Cipher rsa = Cipher.getInstance("RSA");
        rsa.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder().encodeToString(rsa.doFinal(text.getBytes(StandardCharsets.UTF_8)));
    }

    public static String decrypt(Key key, String encryptedText) throws IOException, GeneralSecurityException {
        Cipher rsa = Cipher.getInstance("RSA");
        rsa.init(Cipher.DECRYPT_MODE, key);
        return new String(rsa.doFinal(Base64.getDecoder().decode(encryptedText)), StandardCharsets.UTF_8);
    }


    public static void main(String[] args) throws Exception {
        URL resource = MimbusJoseJwtTest.class.getResource("/rsa/private.pem");
        //URL resource = MimbusJoseJwtTest.class.getResource("/rsa/private-des.pem");

        KeyPair keyPair = readPrivateKey(new FileReader(resource.getFile()));

        String encriptPassword = encrypt(keyPair.getPublic(), "Wallace");
        System.out.println(encriptPassword);

        String decryptPassword = decrypt(keyPair.getPrivate(), encriptPassword);
        System.out.println(decryptPassword);


        String accessToken = accessToken(keyPair);
        System.out.println("accessToken --> " + accessToken);

        boolean accessTokenIsValid = validateAccessToken(keyPair, accessToken);
        System.out.println("Is Valid --> " + accessTokenIsValid);
    }

}
