package se.jj.security;


import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.asn1.x509.Attribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Base64;
import java.util.stream.Stream;


public class AttributeCertificateParser {

    private static final Logger logger = LoggerFactory.getLogger(AttributeCertificateParser.class);

    public record ACInfo(String holderSerial, String notBefore, String notAfter,
                         java.util.Optional<org.bouncycastle.asn1.x500.X500Name> personalNumber, String algorithm, byte[] signature) {
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

            logger.info("Attributes {}", holder.getAttributes().length);
            Stream.of(holder.getAttributes())
                    .forEach(attr -> {
                        logger.info("OID: " + attr.getAttrType().getId());
                        values(attr).forEach(value ->
                                logger.info("  Value: " + value));
                    });

            var first = Stream.ofNullable(holder.getHolder().getEntityNames())
                    .flatMap(Stream::of)
                    .findFirst();

            final ACInfo acInfo = new ACInfo(serial, notBefore, notAfter, first, algorithm, signature);
            logger.info("Parsed data {}", acInfo.toString());
            return acInfo;
        }
    }

    private static Stream<String> values(Attribute attribute) {
        return Stream.of(attribute.getAttributeValues())
                .map(ASN1Encodable::toASN1Primitive)
                .map(ASN1Primitive::toString);
    }
}