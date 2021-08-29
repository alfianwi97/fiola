package alf.security.fiola.utility.logging;

import javax.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import alf.security.fiola.utility.properties.PropertiesLoader;
import ch.qos.logback.classic.AsyncAppender;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.ConsoleAppender;
import ch.qos.logback.core.rolling.FixedWindowRollingPolicy;
import ch.qos.logback.core.rolling.RollingFileAppender;
import ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy;
import ch.qos.logback.core.rolling.SizeBasedTriggeringPolicy;
import ch.qos.logback.core.util.FileSize;

@Configuration
public class LogInitializer {
	@Autowired
	PropertiesLoader propertiesLoader;

	@PostConstruct
	public void init() {
		try {
			propertiesLoader.setLogProperties();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Bean
	public Logger transLogging() {
		return initiateLogger(LogConstants.logTransRollingPolicy, LogConstants.logTransName, LogConstants.logExt,
				LogConstants.logLocation, LogConstants.logPatternLayout, LogConstants.logTransMaxFileSize,
				LogConstants.logTransMaxBackupIndex, LogConstants.logThreshold, LogConstants.logStdoutEnable,
				LogConstants.logTransMaxHistory, LogConstants.logTotalSizeCap);
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	public ch.qos.logback.classic.Logger initiateLogger(String rollingPolicy, String logName, String logExt,
			String logLocation, String patternLayout, String maxFileSize, String maxBackupIndex, String threshold,
			String stdoutEnable, String maxHistory, String totalSizeCap) {

		LoggerContext lc = (LoggerContext) LoggerFactory.getILoggerFactory();
		RollingFileAppender<ILoggingEvent> rollingFileAppender = new RollingFileAppender<ILoggingEvent>();

		AsyncAppender asyncAppender = new AsyncAppender();

		rollingFileAppender.setFile(logLocation + "/" + logName + "." + logExt);
		rollingFileAppender.setContext(lc);
		rollingFileAppender.setName("ROLLINGFILE");

		if (1 == Integer.parseInt(rollingPolicy)) {
			SizeAndTimeBasedRollingPolicy fixWindowRollingPolicy = new SizeAndTimeBasedRollingPolicy();
			fixWindowRollingPolicy.setContext(lc);
			fixWindowRollingPolicy.setParent(rollingFileAppender);
			fixWindowRollingPolicy
					.setFileNamePattern(logLocation + "/archived/" + logName + ".%d{yyyy-MM-dd}.%i" + "." + logExt);
			fixWindowRollingPolicy.setMaxHistory(Integer.parseInt(maxHistory));
			fixWindowRollingPolicy.setMaxFileSize(FileSize.valueOf(maxFileSize));
			fixWindowRollingPolicy.setTotalSizeCap(FileSize.valueOf(totalSizeCap));
			fixWindowRollingPolicy.start();

			rollingFileAppender.setRollingPolicy(fixWindowRollingPolicy);
		} else if (2 == Integer.parseInt(rollingPolicy)) {
			FixedWindowRollingPolicy fixWindowRollingPolicy = new FixedWindowRollingPolicy();
			fixWindowRollingPolicy.setContext(lc);
			fixWindowRollingPolicy.setParent(rollingFileAppender);
			fixWindowRollingPolicy.setFileNamePattern(logLocation + "/archived/" + logName + ".%i" + "." + logExt);
			fixWindowRollingPolicy.setMinIndex(1);
			fixWindowRollingPolicy.setMaxIndex(Integer.parseInt(maxBackupIndex));
			fixWindowRollingPolicy.start();

			SizeBasedTriggeringPolicy<ILoggingEvent> sizeTriggerPolicy = new SizeBasedTriggeringPolicy<ILoggingEvent>();
			sizeTriggerPolicy.setMaxFileSize(FileSize.valueOf(maxFileSize));
			sizeTriggerPolicy.start();

			rollingFileAppender.setRollingPolicy(fixWindowRollingPolicy);
			rollingFileAppender.setTriggeringPolicy(sizeTriggerPolicy);
		}

		PatternLayoutEncoder ple = new PatternLayoutEncoder();
		ple.setContext(lc);
		ple.setPattern(patternLayout);
		ple.start();

		rollingFileAppender.setEncoder(ple);
		// In prudent mode, FileAppender will safely write to the specified file, even
		// in the presence of other FileAppender instances running in different JVMs,
		// potentially running on different hosts. The default value for prudent mode is
		// false.
//		rollingFileAppender.setPrudent(true);
//		rollingFileAppender.setAppend(true);
		rollingFileAppender.start();

		asyncAppender.setContext(lc);
		asyncAppender.addAppender(rollingFileAppender);
		asyncAppender.setDiscardingThreshold(0);
		asyncAppender.setNeverBlock(false);
		asyncAppender.setQueueSize(1000000);
		asyncAppender.setName("ASYNC");
		asyncAppender.start();

		ch.qos.logback.classic.Logger logger = lc.getLogger(logName);
		logger.setLevel(Level.INFO);

		logger.setAdditive(false);
		logger.addAppender(asyncAppender);
		logger.setLevel(Level.toLevel(threshold));

		// detach default CONSOLE appender karena logback.xml tidak ditemukan saat
		// inisiasi app
		ch.qos.logback.classic.Logger root = lc.getLogger(Logger.ROOT_LOGGER_NAME);
		root.detachAppender("CONSOLE");

		if ("Y".equals(stdoutEnable)) {
			logger.setAdditive(false);
			ConsoleAppender ca = new ConsoleAppender();
			ca.setContext(lc);
			ca.setName("CONSOLE");

			PatternLayoutEncoder pleConsole = new PatternLayoutEncoder();
			pleConsole.setContext(lc);
			pleConsole.setPattern("[%X{sessionid}] [%X{userid}] [%X{useragent}] :: %m%n");
			pleConsole.start();

			ca.setEncoder(pleConsole);
			ca.start();

			logger.addAppender(ca);
		}
		return logger;
	}
}
