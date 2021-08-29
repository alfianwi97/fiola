package alf.security.fiola.utility.code.diagnostic.detection;

public class DetectionCode {
	public static final String DC_CLEAN;
	public static final String DC_MISSING_MANDATORY_VALUES;
	public static final String DC_COMMON_INPUT_VIOLATION;
	public static final String DC_FILENAME_LENGTH_VIOLATION;
	public static final String DC_FILE_SIZE_CONSTRAINT_VIOLATION;
	public static final String DC_FILE_FORMAT_NOT_MATCH;
	public static final String DC_CONTAIN_MALLICIOUS_CODE;
	public static final String DC_CONTAIN_MALLICIOUS_FILENAME;
	public static final String DC_FILE_CONSTRAINT_VIOLATION;
	
	static {
		short counter = 0;
		final String detectionCodeString = "DC-";
		final String stringFormat = "%s%03d";
		DC_CLEAN = String.format(stringFormat, detectionCodeString, counter++); //DC-000
		DC_COMMON_INPUT_VIOLATION = String.format(stringFormat, detectionCodeString, counter++); //DC-001
		DC_MISSING_MANDATORY_VALUES = String.format(stringFormat, detectionCodeString, counter++);
		DC_FILENAME_LENGTH_VIOLATION = String.format(stringFormat, detectionCodeString, counter++);
		DC_FILE_SIZE_CONSTRAINT_VIOLATION = String.format(stringFormat, detectionCodeString, counter++);
		DC_FILE_FORMAT_NOT_MATCH = String.format(stringFormat, detectionCodeString, counter++); //DC-005
		DC_CONTAIN_MALLICIOUS_CODE = String.format(stringFormat, detectionCodeString, counter++);
		DC_CONTAIN_MALLICIOUS_FILENAME = String.format(stringFormat, detectionCodeString, counter++);
		DC_FILE_CONSTRAINT_VIOLATION = String.format(stringFormat, detectionCodeString, counter++);
	}
}
