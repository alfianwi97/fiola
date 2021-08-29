package alf.security.fiola.config.spring;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.net.ssl.SSLContext;

import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

@Configuration
public class CustomTrustStrategy {
	public RestTemplate getRestTemplate(HttpComponentsClientHttpRequestFactory clientHttpRequestFactory) throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException, CertificateException, IOException {		
		SSLContextBuilder sslcontextbuilder = SSLContexts.custom();
		sslcontextbuilder.loadTrustMaterial(new TrustSelfSignedStrategy());

		SSLContext sslcontext = sslcontextbuilder.build(); //load trust store

		SSLConnectionSocketFactory sslsockfac = new SSLConnectionSocketFactory(sslcontext,new String[] { "TLSv1","TLSv1.1" },null,NoopHostnameVerifier.INSTANCE);
		
		CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(sslsockfac).build(); //sets up a httpclient for use with ssl socket factory 
		
		clientHttpRequestFactory.setHttpClient(httpClient);
		RestTemplate restTemplate = new RestTemplate(clientHttpRequestFactory);
		return restTemplate;
	}
}
