package se.jj.security;


import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.cert.X509Certificate;

public class AttributeCertificateVerify {

    public boolean verifyAC(byte[] acBytes, X509Certificate issuerCert) throws Exception {
        // Lägg till provider om den inte redan finns
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        try (ASN1InputStream asn1 = new ASN1InputStream(new ByteArrayInputStream(acBytes))) {
            var asn1Obj = asn1.readObject();
            X509AttributeCertificateHolder holder = new X509AttributeCertificateHolder(asn1Obj.toASN1Primitive().getEncoded());

            var verifierBuilder = new JcaContentVerifierProviderBuilder()
                    .setProvider("BC");

            return holder.isSignatureValid(verifierBuilder.build(issuerCert.getPublicKey()));
        }
    }
}