package se.jj.security;


import org.junit.jupiter.api.Test;
import java.nio.file.Path;
import java.security.PublicKey;
import static org.junit.jupiter.api.Assertions.*;


public class PublicKeyLoaderTest {


    @Test
    public void testLoadPublicKey() throws Exception {
        Path keyPath = Path.of("src/test/resources/testkey.pub");


        PublicKeyLoader loader = new PublicKeyLoader();
        PublicKey key = loader.loadPublicKey(keyPath);


        assertNotNull(key);
        assertEquals("RSA", key.getAlgorithm());
    }
}