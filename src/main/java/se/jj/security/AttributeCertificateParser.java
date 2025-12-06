package se.jj.security;


import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Base64;


public class AttributeCertificateParser {

    private static final Logger logger = LoggerFactory.getLogger(AttributeCertificateParser.class);

    public record ACInfo(String holderSerial, String notBefore, String notAfter, String algorithm, byte[] signature) {
    }

    public ACInfo parse(String base64) throws Exception {
        logger.info("Base 64 {}", base64);
        byte[] data = Base64.getDecoder().decode(base64);
        logger.info("Decoded base 64 {}", Arrays.toString(data));

        try (ASN1InputStream asn1 = new ASN1InputStream(new ByteArrayInputStream(data))) {
            var obj = asn1.readObject();
            var holder = new X509AttributeCertificateHolder(obj.toASN1Primitive().getEncoded());

            String serial = holder.getSerialNumber().toString();
            String notBefore = holder.getNotBefore().toString();
            String notAfter = holder.getNotAfter().toString();
            String algorithm  = holder.getSignatureAlgorithm().getAlgorithm().getId();
            byte[] signature = holder.getSignature();
            Arrays.stream(holder.getIssuer().getNames()).forEach(System.out::println);

            final ACInfo acInfo = new ACInfo(serial, notBefore, notAfter, algorithm, signature);
            logger.info("Parsed data {}", acInfo.toString());
            return acInfo;
        }
    }
}