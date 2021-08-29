package alf.security.fiola.utility.properties;

import org.apache.commons.configuration.PropertiesConfiguration;

public class PropertiesConstants {

	public static String appCode;
	public static String appSecretKey;
	public static String appSecretKeyHash;
	public static String appVersion;
	public static String appDesc;
	public static String appLicense;

	public static String connectionTimeout;
	public static String connectionRequestTimeout;
	public static String readTimeout;

	public static String isSwaggerEnable;

	public static long requestBodyMaxSizeInKb;
	
	public static void setAppPropertiesAttributes(PropertiesConfiguration propertiesConfiguration) {
		appCode = (String) propertiesConfiguration.getProperty("app.code");
		appDesc = (String) propertiesConfiguration.getProperty("app.desc");
		appSecretKey = (String) propertiesConfiguration.getProperty("app.secret.key");
		appSecretKeyHash = (String) propertiesConfiguration.getProperty("app.secret.key.hash");
		appVersion = (String) propertiesConfiguration.getProperty("app.version");
		appLicense = (String) propertiesConfiguration.getProperty("app.license");

		connectionTimeout = (String) propertiesConfiguration.getProperty("conf.connection.timeout");
		connectionRequestTimeout = (String) propertiesConfiguration.getProperty("conf.connectionrequest.timeout");
		readTimeout = (String) propertiesConfiguration.getProperty("conf.read.timeout");

		isSwaggerEnable = (String) propertiesConfiguration.getProperty("enable.swagger");
		
		requestBodyMaxSizeInKb = new Long(propertiesConfiguration.getProperty("request.body.max.size.KB").toString());
	}
}
