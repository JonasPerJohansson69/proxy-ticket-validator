package se.jj.security;


import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;

public class ACVerify {

    public boolean verifyAC(byte[] acBytes, X509Certificate issuerCert) throws Exception {
        try (ASN1InputStream asn1 = new ASN1InputStream(new ByteArrayInputStream(acBytes))) {
            var asn1Obj = asn1.readObject();
            X509AttributeCertificateHolder holder = new X509AttributeCertificateHolder(asn1Obj.toASN1Primitive().getEncoded());

            var verifierBuilder = new JcaContentVerifierProviderBuilder()
                    .setProvider("BC");

            return holder.isSignatureValid(verifierBuilder.build(issuerCert.getPublicKey()));
        }
    }
}