package alf.security.fiola.utility.code.diagnostic.detection;

import java.util.HashMap;

import alf.security.fiola.utility.code.returncode.ReturnCode;

public class DetectionCodeMessageMapEnglish {
	private static HashMap<String, String> messageMap;
	public static final String LANGUAGE_CODE = "EN";

	static {
		messageMap = new HashMap<String, String>();
		messageMap.put(ReturnCode.RC_SERVICE_SUCCESS, "Transaction success");
		messageMap.put(ReturnCode.RC_SERVICE_BAD_INPUT, "Invalid input format");
		messageMap.put(ReturnCode.RC_SERVICE_FORBIDDEN, "Access forbidden");
		messageMap.put(ReturnCode.RC_SERVICE_BAD_REQUEST, "Bad Requests");
		messageMap.put(ReturnCode.RC_SERVICE_GENERAL_ERROR, "Error in processing service");

		messageMap.put(ReturnCode.RC_SERVICE_UNSUPPORTED_MEDIA_TYPE, "Unsupported media type");
		messageMap.put(ReturnCode.RC_SERVICE_METHOD_NOT_ALLOWED, "Method not allowed");
		messageMap.put(ReturnCode.RC_SERVICE_NOT_FOUND, "Not Found");
		messageMap.put(ReturnCode.RC_SERVICE_INTERNAL_SERVER_ERROR, "Internal server error");

		messageMap.put(ReturnCode.RC_SERVICE_RELOAD, "Properties Reloaded");

		messageMap.put(ReturnCode.RC_SERVICE_TIMEOUT, "Request Timeout");
	}

	public static String getMessage(String returnMessageCode) {
		return messageMap.get(returnMessageCode);
	}
}
