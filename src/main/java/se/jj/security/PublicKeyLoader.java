package se.jj.security;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


public class PublicKeyLoader {
    Logger logger = LoggerFactory.getLogger(PublicKeyLoader.class);

    public PublicKey loadPublicKey(Path path) throws Exception {
        String pem = Files.readString(path)
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(pem);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        final PublicKey publicKey = keyFactory.generatePublic(keySpec);
        logger.info(publicKey.toString());
        return publicKey;
    }
}