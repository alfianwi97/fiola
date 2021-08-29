package alf.security.fiola.utility.code.returncode;

public class ReturnCode {
	public static final String RC_SERVICE_SUCCESS = "FRC-200";
	public static final String RC_SERVICE_BAD_INPUT = "FRC-400";
	public static final String RC_SERVICE_UNAUTHORIZED = "FRC-401";
	public static final String RC_SERVICE_FORBIDDEN = "FRC-403";
	public static final String RC_SERVICE_BAD_REQUEST = "FRC-409";
	public static final String RC_SERVICE_GENERAL_ERROR = "FRC-499";
	
	/**
	 * @notes Custom exception handler
	 **/
	public static final String RC_SERVICE_UNSUPPORTED_MEDIA_TYPE = "FRC-415";
	public static final String RC_SERVICE_METHOD_NOT_ALLOWED = "FRC-405";
	public static final String RC_SERVICE_NOT_FOUND = "FRC-404";
	public static final String RC_SERVICE_INTERNAL_SERVER_ERROR = "FRC-500";
	
	/**
	 * @notes Reloader return code
	 */
	public static final String RC_SERVICE_RELOAD = "FRC-000";
	
	/**
	 * @notes Timeout code
	 */
	public static final String RC_SERVICE_TIMEOUT = "FRC-408";
	
	
	public static String getMessageIndonesia(String returnMessageCode) {
		return ReturnCodeMessageMapIndonesia.getMessage(returnMessageCode);
	}

	public static String getMessageEnglish(String returnMessageCode) {
		return ReturnCodeMessageMapEnglish.getMessage(returnMessageCode);
	}
}
