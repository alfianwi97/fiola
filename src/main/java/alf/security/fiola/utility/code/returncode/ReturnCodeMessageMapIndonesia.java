package alf.security.fiola.utility.code.returncode;

import java.util.HashMap;

public class ReturnCodeMessageMapIndonesia {
	private static HashMap<String, String> messageMap;
	public static final String LANGUAGE_CODE = "ID";

	static {
		messageMap = new HashMap<String, String>();
		messageMap.put(ReturnCode.RC_SERVICE_SUCCESS, "Transaksi berhasil");
		messageMap.put(ReturnCode.RC_SERVICE_BAD_INPUT, "Format input tidak sesuai");
		messageMap.put(ReturnCode.RC_SERVICE_FORBIDDEN, "Akses tidak diperbolehkan");
		messageMap.put(ReturnCode.RC_SERVICE_BAD_REQUEST, "Format permintaan tidak sesuai");
		messageMap.put(ReturnCode.RC_SERVICE_GENERAL_ERROR, "Terjadi kesalahan dalam proses");

		/**
		 * @notes Custom exception handler
		 **/
		messageMap.put(ReturnCode.RC_SERVICE_UNSUPPORTED_MEDIA_TYPE, "Tipe media tidak sesuai");
		messageMap.put(ReturnCode.RC_SERVICE_METHOD_NOT_ALLOWED, "Metode tidak diperbolehkan");
		messageMap.put(ReturnCode.RC_SERVICE_NOT_FOUND, "Tidak ditemukan");
		messageMap.put(ReturnCode.RC_SERVICE_INTERNAL_SERVER_ERROR, "Error server internal");

		/**
		 * @notes Reloader return messages
		 */
		messageMap.put(ReturnCode.RC_SERVICE_RELOAD, "Properties dimuat ulang");

		/**
		 * @notes time out config
		 */
		messageMap.put(ReturnCode.RC_SERVICE_TIMEOUT, "Waktu proses habis");
	}

	public static String getMessage(String returnMessageCode) {
		return messageMap.get(returnMessageCode);
	}

}
