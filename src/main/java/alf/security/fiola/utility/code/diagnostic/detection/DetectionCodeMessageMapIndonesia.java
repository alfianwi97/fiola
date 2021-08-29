package alf.security.fiola.utility.code.diagnostic.detection;

import java.util.HashMap;

import alf.security.fiola.utility.code.returncode.ReturnCode;

public class DetectionCodeMessageMapIndonesia {
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
		 * @author U060633
		 * @date 9 Oct 2018
		 * @notes Custom exception handler
		 **/
		messageMap.put(ReturnCode.RC_SERVICE_UNSUPPORTED_MEDIA_TYPE, "Tipe media tidak sesuai");
		messageMap.put(ReturnCode.RC_SERVICE_METHOD_NOT_ALLOWED, "Metode tidak diperbolehkan");
		messageMap.put(ReturnCode.RC_SERVICE_NOT_FOUND, "Tidak ditemukan");
		messageMap.put(ReturnCode.RC_SERVICE_INTERNAL_SERVER_ERROR, "Error server internal");

		/**
		 * @author U060633
		 * @date 30 April 2019
		 * @notes Reloader return messages
		 */
		messageMap.put(ReturnCode.RC_SERVICE_RELOAD, "Properties dimuat ulang");

		/**
		 * @author U060633
		 * @date 10 Mei 2019
		 * @notes time out config
		 */
		messageMap.put(ReturnCode.RC_SERVICE_TIMEOUT, "Waktu proses habis");
	}

	public static String getMessage(String returnMessageCode) {
		return messageMap.get(returnMessageCode);
	}

}
