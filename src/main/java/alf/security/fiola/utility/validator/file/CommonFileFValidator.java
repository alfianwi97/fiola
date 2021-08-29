package alf.security.fiola.utility.validator.file;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import alf.security.fiola.utility.common.AppConstants;
import alf.security.fiola.utility.common.BaseComponent;

public class CommonFileFValidator extends BaseComponent{
	
	public static boolean checkFileBytesContentSizeInKB(byte[] fileBytesContent, long minSizeInKB, long maxSizeInKB)
			throws Exception {
		transLog.info("Checking file base64 content size . . .");
		if (fileBytesContent == null)
			throw new Exception("Invalid ImageBase64 : null");
		if (minSizeInKB < 0 || maxSizeInKB < 0 || maxSizeInKB < minSizeInKB)
			throw new Exception("Invalid size validation (min:" + minSizeInKB + ", max:" + maxSizeInKB + ")");

		double fileSizeInKB = fileBytesContent.length / 1024;

		transLog.info("Detected size in KB: "+fileSizeInKB);
		if (fileSizeInKB < minSizeInKB || fileSizeInKB > maxSizeInKB)
			return false;
		return true;
	}
	
	public static boolean isFilenameSafe(String filename) {
		String pattern = AppConstants.FILENAME_VALID_REGEX_PATTERN;
		Pattern r = Pattern.compile(pattern);
		Matcher m = r.matcher(filename);
		return m.matches();
	}
	
	public static boolean isFilenameLengthFit(String filename, int maxLength) {
		return filename.length() <= maxLength;
	}
	public static boolean isFilenameLengthFit(String filename, int minLength, int maxLength) {
		return filename.length() >= minLength && filename.length() <= maxLength;
	}
}
