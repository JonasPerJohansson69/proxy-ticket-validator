Textsträngen du har är en Base64-kodad ASN.1-struktur som innehåller ett X.509 Attribute Certificate (AC), 
inte en vanlig digital signatur och inte ett vanligt personcertifikat. 
Det är en Svenskt myndighets-issued Attribute Certificate, typiskt från TRM/Plikt- och prövningsverket.

X509AttributeCertificate

Exakt tolkning (vad du med mycket hög sannolikhet har)

Ett testcertifikat (subject: Pliktverket AM AA test), utfärdat av en Test CA (TRM Test CA v1).

Kryptering: RSA-public key + signatur med SHA-1 + RSA.

Giltighet: 2025-12-05 07:48:25 → 2025-12-05 08:08:55 (ca 20 minuter).

Extensions: AuthorityInfoAccess (AIA) med lokal URL, SubjectAltName med åtminstone en ipAddress och andra fält som pekar mot interna tjänster (minsida.pliktverket.local), plus LoA-URL http://id.elegnamnden.se/loa/1.0/loa2.

mvn -DskipTests package

# 2) För att generera test certifikat kör programmet (jar-with-dependencies skapas av assembly-plugin)
java -jar target/proxy-ticket-validator-1.0-SNAPSHOT-jar-with-dependencies.jar

`@Inject
DomainCacertsLoader cacerts;

public void verifyCert() {
cacerts.listAliases();

    Certificate cert = cacerts.getCertificate("myservercert");
    if (cert != null) {
        System.out.println("Certifikat hittat: " + cert);
    }
}
`