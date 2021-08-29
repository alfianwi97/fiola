package alf.security.fiola.utility.code.diagnostic.state;

import java.util.HashMap;

import alf.security.fiola.utility.code.returncode.ReturnCode;

public class StateCodeMessageMapIndonesia {
	private static HashMap<String, String> messageMap;
	public static final String LANGUAGE_CODE = "ID";

	static {
		messageMap = new HashMap<String, String>();
		messageMap.put(ReturnCode.RC_SERVICE_SUCCESS, "Transaksi berhasil");
		messageMap.put(ReturnCode.RC_SERVICE_BAD_INPUT, "Format input tidak sesuai");
		messageMap.put(ReturnCode.RC_SERVICE_FORBIDDEN, "Akses tidak diperbolehkan");
		messageMap.put(ReturnCode.RC_SERVICE_BAD_REQUEST, "Format permintaan tidak sesuai");
		messageMap.put(ReturnCode.RC_SERVICE_GENERAL_ERROR, "Terjadi kesalahan dalam proses");

		messageMap.put(ReturnCode.RC_SERVICE_UNSUPPORTED_MEDIA_TYPE, "Tipe media tidak sesuai");
		messageMap.put(ReturnCode.RC_SERVICE_METHOD_NOT_ALLOWED, "Metode tidak diperbolehkan");
		messageMap.put(ReturnCode.RC_SERVICE_NOT_FOUND, "Tidak ditemukan");
		messageMap.put(ReturnCode.RC_SERVICE_INTERNAL_SERVER_ERROR, "Error server internal");

		messageMap.put(ReturnCode.RC_SERVICE_RELOAD, "Properties dimuat ulang");

		messageMap.put(ReturnCode.RC_SERVICE_TIMEOUT, "Waktu proses habis");
	}

	public static String getMessage(String returnMessageCode) {
		return messageMap.get(returnMessageCode);
	}

}