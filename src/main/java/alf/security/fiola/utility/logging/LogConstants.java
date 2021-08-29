package alf.security.fiola.utility.logging;

import org.apache.commons.configuration.PropertiesConfiguration;

public class LogConstants {

	public static String logPatternLayout = "";
	public static String logExt = "";
	public static String logLocation = "";
	public static String logThreshold = "";
	public static String logStdoutEnable = "";
	public static String logTotalSizeCap = "";

	public static String logTransRollingPolicy = "";
	public static String logTransName = "";
	public static String logTransMaxFileSize = "";
	public static String logTransMaxBackupIndex = "";
	public static String logTransMaxHistory = "";

	public static void setLogPropertiesAttributes(PropertiesConfiguration propertiesConfiguration) {

		logPatternLayout = (String) propertiesConfiguration.getProperty("log.patternLayout");
		logExt = (String) propertiesConfiguration.getProperty("log.ext");
		logLocation = (String) propertiesConfiguration.getProperty("log.location");
		logThreshold = (String) propertiesConfiguration.getProperty("log.threshold");
		logStdoutEnable = (String) propertiesConfiguration.getProperty("log.stdoutEnable");
		logTotalSizeCap = (String) propertiesConfiguration.getProperty("log.totalSizeCap");

		logTransRollingPolicy = (String) propertiesConfiguration.getProperty("log.trans.rollingPolicy");
		logTransName = (String) propertiesConfiguration.getProperty("log.trans.logName");
		logTransMaxFileSize = (String) propertiesConfiguration.getProperty("log.trans.maxFileSize");
		logTransMaxBackupIndex = (String) propertiesConfiguration.getProperty("log.trans.maxBackupIndex");
		logTransMaxHistory = (String) propertiesConfiguration.getProperty("log.trans.maxHistory");
	}

}
