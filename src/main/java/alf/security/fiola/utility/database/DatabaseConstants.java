package alf.security.fiola.utility.database;

import org.apache.commons.configuration.PropertiesConfiguration;

public class DatabaseConstants {

	public static String fiolaAppCode;
	public static String fiolaDatasource;
	public static String fiolaDbSchema;
	public static String fiolaDbConn;
	
	public static void setDatasourcePropertiesAttributes(PropertiesConfiguration propertiesConfiguration) {
		fiolaAppCode = (String) propertiesConfiguration.getProperty("fiola.app.code");
		fiolaDatasource = (String) propertiesConfiguration.getProperty("fiola.datasource");
		fiolaDbSchema = (String) propertiesConfiguration.getProperty("fiola.db.schema");
		fiolaDbConn = (String) propertiesConfiguration.getProperty("fiola.db.conn");
	}
}
