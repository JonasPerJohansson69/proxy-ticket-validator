Textsträngen du har är en Base64-kodad ASN.1-struktur som innehåller ett X.509 Attribute Certificate (AC), 
inte en vanlig digital signatur och inte ett vanligt personcertifikat. 
Det är en Svenskt myndighets-issued Attribute Certificate, typiskt från TRM/Plikt- och prövningsverket.


mvn -DskipTests package

# 2) kör programmet (jar-with-dependencies skapas av assembly-plugin)
java -jar target/proxy-ticket-validator-1.0-SNAPSHOT-jar-with-dependencies.jar