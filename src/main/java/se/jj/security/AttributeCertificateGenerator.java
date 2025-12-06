package se.jj.security;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.AttributeCertificateHolder;
import org.bouncycastle.cert.AttributeCertificateIssuer;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509v2AttributeCertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

/**
 * Simple generator that produces:
 * - issuer.der (issuer X.509 certificate, self-signed)
 * - ac.crr (X.509 Attribute Certificate, DER encoded)
 * <p>
 * NOTE: For demo/test use only. Adjust fields, OIDs, keys and lifetimes for production.
 */
public class AttributeCertificateGenerator {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // 1) Generate issuer keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair issuerKP = kpg.generateKeyPair();

        // Issuer DN
        X500Name issuerName = new X500Name("CN=TRM Test CA v1, O=Totalsf\u00f6rsvarets Rekryteringsmyndighet, C=SE");

        // 2) Create a self-signed X.509 issuer certificate (valid 2 years)
        BigInteger issuerSerial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60);
        Calendar cal = Calendar.getInstance();
        cal.setTime(notBefore);
        cal.add(Calendar.YEAR, 2);
        Date notAfter = cal.getTime();

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerName,
                issuerSerial,
                notBefore,
                notAfter,
                issuerName,
                issuerKP.getPublic()
        );

        ContentSigner issuerSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(issuerKP.getPrivate());

        X509Certificate issuerCert = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certBuilder.build(issuerSigner));

        // Save issuer cert to issuer.der (DER)
        try (FileOutputStream fos = new FileOutputStream("src/test/resources/issuer.der")) {
            fos.write(issuerCert.getEncoded());
        }
        System.out.println("Wrote issuer.der");

        // 3) Prepare attribute-certificate holder (the subject to whom attributes apply)
        // We'll create a "subject" X500Name (the holder)
        X500Name holderName = new X500Name("CN=Pliktverket AM AA test, O=Pliktverket, C=SE");

        AttributeCertificateHolder holder = new AttributeCertificateHolder(holderName);

        // 4) Attribute certificate issuer (who signs the AC)
        AttributeCertificateIssuer acIssuer = new AttributeCertificateIssuer(issuerName);

        // 5) Build the Attribute Certificate
        BigInteger acSerial = BigInteger.valueOf(System.currentTimeMillis() & 0xffffffffL);

        // Validity: short lived example (20 minutes)
        Date acNotBefore = new Date(System.currentTimeMillis() - 1000L * 30);
        Date acNotAfter = new Date(System.currentTimeMillis() + 1000L * 60 * 20);

        X509v2AttributeCertificateBuilder acBuilder =
                new X509v2AttributeCertificateBuilder(holder, acIssuer, acSerial, acNotBefore, acNotAfter);

        // Add a sample attribute (OID arbitrarily chosen for demo). In real systems use app-specific OIDs.
        ASN1ObjectIdentifier attrOid = new ASN1ObjectIdentifier("1.2.840.113549.1.9.1"); // emailAddress OID (PKCS#9) as an example
        // single string value
        acBuilder.addAttribute(attrOid, new DERUTF8String("testuser@example.org"));

        // Add SubjectAltName-like extension as example (ipAddress)
        GeneralName gn = new GeneralName(GeneralName.iPAddress, "10.54.17.26");
        GeneralNames gns = new GeneralNames(gn);
        acBuilder.addExtension(Extension.subjectAlternativeName, false, gns);

        // Sign the AC with issuer's private key
        ContentSigner acSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(issuerKP.getPrivate());

        X509AttributeCertificateHolder attributeCertificateHolder = acBuilder.build(acSigner);

        // Write attribute certificate (DER) to ac.crr
        try (FileOutputStream fos = new FileOutputStream("src/test/resources/ac.crr")) {
            fos.write(attributeCertificateHolder.getEncoded());
        }
        System.out.println("Wrote ac.crr");
        System.out.println("AC serial: " + acSerial);
    }
}
