package se.jj.security;


import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertTrue;


public class ACVerifyTest {


    @Test
    public void testVerifyAC() throws Exception {
        byte[] acBytes = Files.readAllBytes(Path.of("src/test/resources/ac.crr"));
        byte[] issuerBytes = Files.readAllBytes(Path.of("src/test/resources/issuer.der"));

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate issuer = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(issuerBytes));


        ACVerify verifier = new ACVerify();
        boolean result = verifier.verifyAC(acBytes, issuer);


        assertTrue(result, "Attribute certificate signature should verify");
    }
}