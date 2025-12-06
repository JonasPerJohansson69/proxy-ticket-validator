package se.jj.security;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Enumeration;

@ApplicationScoped
public class DomainCacertsLoader {

    private KeyStore trustStore;

    @PostConstruct
    void init() {
        try {
            // Payara sätter denna systemproperty automatiskt:
            // com.sun.aas.instanceRoot = payara/domains/<domain>
            String instanceRoot = System.getProperty("com.sun.aas.instanceRoot");

            if (instanceRoot == null) {
                throw new IllegalStateException("Payara instanceRoot saknas!");
            }

            // Hitta cacerts-fil i domain/config/
            File confFolder = new File(instanceRoot, "config");

            // Vissa installationer använder 'cacerts', andra 'cacerts.jks'
            File cacerts = new File(confFolder, "cacerts");
            if (!cacerts.exists()) {
                cacerts = new File(confFolder, "cacerts.jks");
            }

            if (!cacerts.exists()) {
                throw new IllegalStateException("Hittar ingen cacerts-fil i: " + confFolder);
            }

            trustStore = KeyStore.getInstance("JKS");

            try (FileInputStream fis = new FileInputStream(cacerts)) {
                // Standardlösenord i Payara/JDK "cacerts"
                trustStore.load(fis, "changeit".toCharArray());
            }

            System.out.println("✓ Cacerts laddad från: " + cacerts.getAbsolutePath());

        } catch (Exception e) {
            throw new RuntimeException("Kunde inte ladda domain cacerts", e);
        }
    }

    public KeyStore getTrustStore() {
        return trustStore;
    }

    public Certificate getCertificate(String alias) {
        try {
            return trustStore.getCertificate(alias);
        } catch (Exception e) {
            throw new RuntimeException("Kunde inte hämta certifikat för alias " + alias, e);
        }
    }

    public void listAliases() {
        try {
            Enumeration<String> aliases = trustStore.aliases();
            while (aliases.hasMoreElements()) {
                System.out.println("Alias: " + aliases.nextElement());
            }
        } catch (Exception e) {
            throw new RuntimeException("Kunde inte lista alias", e);
        }
    }
}
