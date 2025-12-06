package se.jj.security;


import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import java.io.ByteArrayInputStream;
import java.util.Base64;


public class ACParser {


    public record ACInfo(String holderSerial, String issuerCN, String notBefore, String notAfter) {}


    public ACInfo parse(String base64) throws Exception {
        byte[] data = Base64.getDecoder().decode(base64);


        try (ASN1InputStream asn1 = new ASN1InputStream(new ByteArrayInputStream(data))) {
            var obj = asn1.readObject();
            var holder = new X509AttributeCertificateHolder(obj.toASN1Primitive().getEncoded());


            String serial = holder.getSerialNumber().toString();
            String issuerCN = holder.getIssuer().getNames()[0].getDirectoryString().toString();
            String notBefore = holder.getNotBefore().toString();
            String notAfter = holder.getNotAfter().toString();


            return new ACInfo(serial, issuerCN, notBefore, notAfter);
        }
    }
}