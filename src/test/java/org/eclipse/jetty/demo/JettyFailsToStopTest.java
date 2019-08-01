package org.eclipse.jetty.demo;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.Collection;
import javax.net.ssl.SSLHandshakeException;

import okhttp3.Call;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okio.ByteString;
import org.eclipse.jetty.alpn.server.ALPNServerConnectionFactory;
import org.eclipse.jetty.http2.server.HTTP2ServerConnectionFactory;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.NetworkConnector;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.thread.QueuedThreadPool;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public final class JettyFailsToStopTest
{
    private static char[] password = "password".toCharArray(); // Any password will work.
    private final Server server = new Server(new QueuedThreadPool());

    @Test
    public void test()
    {
        Assertions.assertTimeout(Duration.ofSeconds(5), () ->
        {
            startJetty();
            makeOkHttpCall();
            stopJetty();
        });
    }

    final void startJetty() throws Exception
    {
        HttpConfiguration httpConfig = new HttpConfiguration();
        httpConfig.setSendServerVersion(false);
        httpConfig.setSecurePort(0);
        SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();

        sslContextFactory.setKeyStore(newServerKeyStore());
        sslContextFactory.setKeyStorePassword(new String(password));
        HttpConfiguration httpsConfig = new HttpConfiguration(httpConfig);
        httpsConfig.addCustomizer(new SecureRequestCustomizer());
        ALPNServerConnectionFactory alpn = new ALPNServerConnectionFactory("h2", "http/1.1");
        alpn.setDefaultProtocol("http/1.1");
        SslConnectionFactory ssl = new SslConnectionFactory(sslContextFactory, alpn.getProtocol());
        HTTP2ServerConnectionFactory http2 = new HTTP2ServerConnectionFactory(httpsConfig);
        HttpConnectionFactory http1 = new HttpConnectionFactory(httpsConfig);

        ServerConnector httpsConnector = new ServerConnector(
            server, null, null, null, -1, -1, ssl, alpn, http2, http1);
        httpsConnector.setReuseAddress(true);
        httpsConnector.setHost("localhost");
        server.addConnector(httpsConnector);

        ServletContextHandler servletContextHandler = new ServletContextHandler();
        server.addManaged(servletContextHandler);

        server.setStopAtShutdown(true);
        server.setStopTimeout(5100L);

        server.setHandler(servletContextHandler);
        server.start();
    }

    private void makeOkHttpCall() throws Exception
    {
        try
        {
            OkHttpClient client = new OkHttpClient();
            Call call = client.newCall(new Request.Builder()
                .url("https://localhost:" + httpsPort() + "/")
                .build());
            call.execute();
            throw new AssertionError("expected handshake failure");
        }
        catch (SSLHandshakeException expected)
        {
            System.out.println("received expected handshake failure: " + expected);
        }
    }

    final void stopJetty() throws Exception
    {
        server.stop();
    }

    int httpsPort()
    {
        for (Connector connector : server.getConnectors())
        {
            if (connector instanceof NetworkConnector)
            {
                return ((NetworkConnector)connector).getLocalPort();
            }
        }
        throw new IllegalStateException();
    }

    private KeyStore newServerKeyStore() throws Exception
    {
        Certificate serverCert = decodePem(""
            + "-----BEGIN CERTIFICATE-----\n"
            + "MIIDgDCCAmigAwIBAgIELqf3DTANBgkqhkiG9w0BAQsFADBoMQswCQYDVQQGEwJV\n"
            + "UzELMAkGA1UECBMCQ0ExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xDTALBgNVBAoT\n"
            + "BE1pc2sxDzANBgNVBAsTBlNlcnZlcjEUMBIGA1UEAxMLbWlzay1zZXJ2ZXIwHhcN\n"
            + "MTgwMjIzMTE0MTE1WhcNMjMwMTI4MTE0MTE1WjBoMQswCQYDVQQGEwJVUzELMAkG\n"
            + "A1UECBMCQ0ExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xDTALBgNVBAoTBE1pc2sx\n"
            + "DzANBgNVBAsTBlNlcnZlcjEUMBIGA1UEAxMLbWlzay1zZXJ2ZXIwggEiMA0GCSqG\n"
            + "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCUa8oMfvtOfhRsoSx8H188Qn40piXaVthg\n"
            + "GwzUpsi+7BESnOaKww4inbpBZDBiAu7JJj3UefHt+bOsOHS1xh6knjxzLg2mO/a2\n"
            + "pfL33xKrAKcHFy33fTEN107t9GS2S3eI8wQAyo6jtTudZIcgZsFNIc5+T+i8ec6k\n"
            + "djzpuxJAGt85ppZiO7wsbCpx40t3NowQqsBCJSqVTarnxw5U7hohac2t8kcs8TPX\n"
            + "uYOgCo7UgK17iS3tMLHkDdXCtXM6v6GUwXx8BhP/KRTydp5AaUAK/nXw7YROPjWn\n"
            + "qqu2S29d5dTPwqzySirX+rcwcbilpgmyZ4zWkDP96XwBTEg67szHAgMBAAGjMjAw\n"
            + "MB0GA1UdDgQWBBQWGVweG5jfzvB5EbPdMOByFj4Q0zAPBgNVHREECDAGhwR/AAAB\n"
            + "MA0GCSqGSIb3DQEBCwUAA4IBAQASRR4P1ADIxi5fARYqR28TIAykcCeJyflSWv0C\n"
            + "ffgmTQ7BFaNBfaVLnVfjkdBUVV4uK2nf/Eepp3Lax9vMtq4idkOTkLJ5dE5EId+2\n"
            + "kyjNbpsaS2tti31B4JSp0LHAIbOTi3ERcdkucfqGyN6mmOlsas3er7TfWoQjdRjg\n"
            + "Qr5SZL39LOcHDgEKpFWOfoAsYdkgg4+//pv+RCmR/uzGrPG+lbyFe39PM+t3jQ7/\n"
            + "GEn/eW8WzpS2/t2kyAHIiuRujYRcH10CuoY/bIcZIa/RJXRDlL6Wap/5sc6KWP0x\n"
            + "2BQ2mqZcNY3aNZJv0yfNJ76lMdYfW29eHy5mF246GRbFGIYm\n"
            + "-----END CERTIFICATE-----\n");

        PrivateKey serverPrivateKey = decodePrivateKey(""
            + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCUa8oMfvtOfhRs\n"
            + "oSx8H188Qn40piXaVthgGwzUpsi+7BESnOaKww4inbpBZDBiAu7JJj3UefHt+bOs\n"
            + "OHS1xh6knjxzLg2mO/a2pfL33xKrAKcHFy33fTEN107t9GS2S3eI8wQAyo6jtTud\n"
            + "ZIcgZsFNIc5+T+i8ec6kdjzpuxJAGt85ppZiO7wsbCpx40t3NowQqsBCJSqVTarn\n"
            + "xw5U7hohac2t8kcs8TPXuYOgCo7UgK17iS3tMLHkDdXCtXM6v6GUwXx8BhP/KRTy\n"
            + "dp5AaUAK/nXw7YROPjWnqqu2S29d5dTPwqzySirX+rcwcbilpgmyZ4zWkDP96XwB\n"
            + "TEg67szHAgMBAAECggEABJTbNM2Kpl6f9MZ44A/72ZlX2foy+u1pWnYbTEklszcI\n"
            + "Q+HSAACLZCgoQrJ8B9p9Uno6uF9XR3hIwo0vlRjbg0tbJFcMltANCpBO0rXxFpQ7\n"
            + "k610fso/hGTcC95aaYIk23Zc7kVSZ91FTNN4lFh3qRDdFesTjRXZehwoPzLGGnJt\n"
            + "xJ0rfNgAnKXZAhIzrmpSpCZ/xJUKrCa11uSUDRf8ljshBsA59sPjNMdE/Ab+UssT\n"
            + "GeW3oWILfb6g/ghiQ1pTu27hDBU+leUfNInwc8c7BLYXgk8eGPHcVjZRX4SN2aX6\n"
            + "jefvdzfPtqEPnAzG7qrRp2z3kFMGKguiiUwpBHciEQKBgQDeEyqCFN/DjOo0hGZl\n"
            + "BfXs41BvwN3mGCUuV/EXPBI4F2GMJCgpfz0LF7CFoo+9hdXWl/uL+3wQDdJ4RKMV\n"
            + "2qjo2l4/bf6/LvTgjEvdfEc0NY49Cp7Nhg5Ndf0X6j9Yd5BAxckjNDIudyROUpSF\n"
            + "HSqY5BBRlQILn04l5RkdTL07zwKBgQCrGDFnsYVLLKxljOheM8BMW2W2viumB82A\n"
            + "iPMT3UBmYJ/zWUp35+7hKwgi51ZUDhRDuI0PRCCXO9UGF8anT5Axm9Ah+qFg0UDY\n"
            + "snSHmoo34PCjJYAkPDvkpD6ma4C3lgACJcCsJK+4v2UfNB5fxH7xeJdkF9kCpoJ1\n"
            + "wUCrCoVFiQKBgQDTVUvrlK/I6W3r4l+LHdwFveDLKLBCipG/g4L0SH9SD7YN5k6u\n"
            + "Bt7xkm6zDZtakWWJHQMOGJncsTqspyzH3FlHlp+AH04BZE827Ww4707XeWvN3TB4\n"
            + "h21O+8yKGKqFpuqJKW+a584ld83+Fwotjy79ZnO9H19d7hExcM6wmlmu8wKBgBN8\n"
            + "ZeQRa8TsCZZnPe+8pSINJsBxWDdInDcPYd/ZSwRd7NmiScDuQV6TsBGJl2NrVxN/\n"
            + "aVFbyPpwbgqLmqxje2CrBkFYchi8vE3xxSPMjgFfNQjftIBr+8ZGjnwVsks2Yjnc\n"
            + "Yt04MGsyISo0nWD62BpYSaW0sZqDrEgNAnh4ckVBAoGAb3C+y00jAwdo+6jOgkwT\n"
            + "poGTpz65gYaTV7uo1GliYVU67ooekEiJnzaQiKrzqDaoZWzAgrUy2zcGO1Qo9QRD\n"
            + "ZVOELBhhYuGdiDOkI/fS3siyUUZbNz8cnoz2uVSW5sz5X45H9aopnfhJctZD2/Tj\n"
            + "IZmh94FV3s380ji5A+HMaPo=\n"
        );

        KeyStore keyStore = newEmptyKeyStore();
        Certificate[] certificates = {serverCert};
        keyStore.setKeyEntry("private", serverPrivateKey, password, certificates);
        return keyStore;
    }

    private static KeyStore newEmptyKeyStore() throws Exception
    {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, password);
        return keyStore;
    }

    private static Certificate decodePem(String pem) throws Exception
    {
        Collection<? extends Certificate> certificates = CertificateFactory.getInstance("X.509")
            .generateCertificates(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
        return certificates.iterator().next();
    }

    private static PrivateKey decodePrivateKey(String privateKeyBase64) throws Exception
    {
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
            ByteString.decodeBase64(privateKeyBase64).toByteArray());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(privateKeySpec);
    }
}