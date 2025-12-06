package se.jj.security;


import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;


public class ACParserTest {


    private static final String AC_BASE64 = "MIIDGjCCAgICAQEwHaEbpBkwFzEVMBMGA1UEBRMMMjAwNTAzMjAyMzg0oIG7MFekVTBTMQswCQYDVQQGEwJTRTEjMCEGA1UEChQaUGxpa3QtIG9jaCBwcvZ2bmluZ3N2ZXJrZXQxHzAdBgNVBAMTFlBsaWt0dmVya2V0IEFNIEFBIHRlc3SgYDBapFgwVjELMAkGA1UEBhMCU0UxLjAsBgNVBAoUJVRvdGFsZvZyc3ZhcmV0cyBSZWtyeXRlcmluZ3NteW5kaWdoZXQxFzAVBgNVBAMTDlRSTSBUZXN0IENBIHYxAgIECDANBgkqhkiG9w0BAQUFAAIJAPfVp1iAflixMCIYDzIwMjUxMjA1MDc0ODI1WhgPMjAyNTEyMDUwODA4NTVaMAAwgd8wCQYDVR04BAIFADBGBgNVHTcBAf8EPDA6oDiGNmh0dHBzOi8vbWluc2lkYS5wbGlrdHZlcmtldC5sb2NhbDo4NDQzL3BlcnNvbi9taW4tc2lkYTA7BgYqhXA2DQEEMTAvDAZwYXNzd2QWJWh0dHA6Ly9pZC5lbGVnbmFtbmRlbi5zZS9sb2EvMS4wL2xvYTIwTQYGKoVwNg0CBEMwQTAYFglpcEFkZHJlc3MMCzEwLjU0LjE3LjI2MCUWDWF1dGhSZWZlcmVuY2UMFDZGOU94cnhpQjU5SVBrSXlPVmtoMA0GCSqGSIb3DQEBBQUAA4IBAQCUNLODn0y+YWsKjUE2/CeVK+7iBaM1bZ6t63pg1JJbWmHDycafCjdK0LXAjzHzksLtl1BH8ZJFTHwxGHr0V3bX/EBEt/S/WrEGFi2yCw+nM58st6nOBTKqkq7b7gThr+GrbGiVf7nIIntKz4Eyindd5bfmKhDli+bZImvrcoy3wF3PZd7l5PXn9456mo/PeEV/9Q3rfWfxX7bIdccnsOxb0tTLLJ5FV12DbZiqPEpcudhbW2OPQ+C12vniQAjLIStZN1pUpaBgWDK3mGFEmoQ0ZXgZEJv3JKgFdbKmeo96aDbhLqE2/tyRQzn7sLC09sH/WTwlMXWSfInNy98ObxOY";


    @Test
    public void testParse() throws Exception {
        ACParser parser = new ACParser();
        ACParser.ACInfo info = parser.parse(AC_BASE64);


        assertNotNull(info.serial());
        assertNotNull(info.issuerCN());
        assertNotNull(info.notBefore());
        assertNotNull(info.notAfter());
    }
}