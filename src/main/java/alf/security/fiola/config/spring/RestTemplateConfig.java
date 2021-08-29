package alf.security.fiola.config.spring;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import alf.security.fiola.utility.properties.PropertiesConstants;

/**
 * @notes time out config
 */
@Configuration
public class RestTemplateConfig {

	@Bean
	public RestTemplate restTemplate() {
		RestTemplate restTemplate = new RestTemplate(clientHttpRequestFactory());
		return restTemplate;
	}
	
	@Bean
	@Qualifier("sslRestTemplate")
	public RestTemplate sslRestTemplate() {
		RestTemplate restTemplate = null;
		try {
			restTemplate = new CustomTrustStrategy().getRestTemplate(clientHttpRequestFactory());
		} catch (KeyManagementException | KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			e.printStackTrace();
		}
		return restTemplate;
	}

	@Bean
	public HttpComponentsClientHttpRequestFactory clientHttpRequestFactory() {
		HttpComponentsClientHttpRequestFactory httpRequestFactory = new HttpComponentsClientHttpRequestFactory();
		httpRequestFactory.setConnectionRequestTimeout(Integer.parseInt(PropertiesConstants.connectionRequestTimeout) * 1000);
		httpRequestFactory.setConnectTimeout(Integer.parseInt(PropertiesConstants.connectionTimeout) * 1000);
		httpRequestFactory.setReadTimeout(Integer.parseInt(PropertiesConstants.readTimeout) * 1000);
		return httpRequestFactory;
	}
}
