package alf.security.fiola.utility.common;

import java.util.regex.Pattern;

public class FileBase64Utils extends BaseComponent{
	public static boolean isFileContainBase64Header(String fileBase64) {
		Pattern p = Pattern.compile(AppConstants.FILE_BASE64_HEADER_PATTERN);
		return p.matcher(fileBase64).find();
	}
	
	public static String getFileBase64Header(String fileBase64) {
		transLog.info("Start to get image header . . .");
		
		if(!FileBase64Utils.isFileContainBase64Header(fileBase64)) {
			transLog.info("File does not have a base64 file header . . .");
			return null;
		}
			
		String[] splitComa = fileBase64.split(",");
		transLog.info("Detected file base64 header : {}", splitComa[0]);
		transLog.info("Finish to get image header . . .");
		return splitComa[0];
	}
	
	public static String getFileBase64Extension(String fileBase64) {
		transLog.info("Start to get image extension . . .");
		
		if(!FileBase64Utils.isFileContainBase64Header(fileBase64)) {
			transLog.info("File does not have a base64 file header . . .");
			return null;
		}
		
		String extension = null;
		String fileBase64Header = getFileBase64Header(fileBase64);
		String[] splitSemicolon = fileBase64Header.split(";");
		String[] splitSlash = splitSemicolon[0].split("/");
		extension = splitSlash[1];
		
		transLog.info("Detected file base64 extension : {}", extension);
		transLog.info("Finish to get image extension . . .");
		return extension;
	}
	
	public static String getFileBase64Content(String fileBase64) {
		transLog.info("Start to get base64 content . . .");
		String[] splitComa = fileBase64.split(",");
		
		transLog.info("Finish to get base64 content . . .");
		return splitComa.length == 1 ? splitComa[0] : splitComa[1];
	}
}
