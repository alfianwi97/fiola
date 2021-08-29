package alf.security.fiola.utility.properties;

import javax.annotation.PostConstruct;

import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;

import alf.security.fiola.utility.database.DatabaseConstants;
import alf.security.fiola.utility.logging.LogConstants;

@Configuration
@PropertySource(value = { "classpath:application.properties" })
public class PropertiesLoader {

	@Autowired
	private Environment environment;

	private PropertiesConfiguration propertiesConfiguration;

	String appPropertiesLocation;
	String logPropertiesLocation;
	String dbPropertiesLocation;

	@PostConstruct
	public void getSystemProperties() throws Exception {
		try {
			String configPath = environment.getRequiredProperty("config.path");
			propertiesConfiguration = new PropertiesConfiguration(configPath + "/system.properties");
			appPropertiesLocation = configPath + "/" + propertiesConfiguration.getProperty("app.properties").toString();
			logPropertiesLocation = configPath + "/" + propertiesConfiguration.getProperty("log.properties").toString();
			dbPropertiesLocation = configPath + "/" + propertiesConfiguration.getProperty("db.properties").toString();
			setAppProperties();
			setLogProperties();
			setDatasourceProperties();
		} catch (ConfigurationException e) {
			throw new Exception(e);
		}
	}

	public void setAppProperties() throws Exception {
		try {
			propertiesConfiguration = new PropertiesConfiguration(appPropertiesLocation);
			PropertiesConstants.setAppPropertiesAttributes(propertiesConfiguration);
		} catch (ConfigurationException e) {
			throw new Exception(e);
		}
	}

	public void setLogProperties() throws Exception {
		try {
			propertiesConfiguration = new PropertiesConfiguration(logPropertiesLocation);
			LogConstants.setLogPropertiesAttributes(propertiesConfiguration);
		} catch (ConfigurationException e) {
			throw new Exception(e);
		}
	}

	public void setDatasourceProperties() throws Exception {
		try {
			propertiesConfiguration = new PropertiesConfiguration(dbPropertiesLocation);
			DatabaseConstants.setDatasourcePropertiesAttributes(propertiesConfiguration);
		} catch (ConfigurationException e) {
			throw new Exception(e);
		}
	}

}
