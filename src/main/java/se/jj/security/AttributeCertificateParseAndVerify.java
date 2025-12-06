package se.jj.security;


import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;


public class AttributeCertificateParseAndVerify {

    private static final Logger logger = LoggerFactory.getLogger(AttributeCertificateParseAndVerify.class);

    public boolean parseAndVerify(String base64, PublicKey publicKey) throws Exception {
        // Lägg till provider om den inte redan finns
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        byte[] data = Base64.getDecoder().decode(base64);

        try (ASN1InputStream asn1 = new ASN1InputStream(new ByteArrayInputStream(data))) {
            var obj = asn1.readObject();
            var holder = new X509AttributeCertificateHolder(obj.toASN1Primitive().getEncoded());
            ContentVerifierProvider verifierProvider =
                    new JcaContentVerifierProviderBuilder()
                            .setProvider("BC")
                            .build(publicKey);
            boolean isValid = holder.isSignatureValid(verifierProvider);

            logger.info("Signature is valid {}", isValid);
            return isValid;
        }
    }
}