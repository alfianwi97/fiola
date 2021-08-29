package alf.security.fiola.utility.code.diagnostic;

import alf.security.fiola.utility.code.diagnostic.detection.DetectionCode;

public class DiagnosticFactory {
	public static Diagnostic fileFormatNotMatch(String msg) {
		Diagnostic d = new Diagnostic();
		d.setDetectionCode(DetectionCode.DC_FILE_FORMAT_NOT_MATCH);
		d.setMessage(msg);
		return d;
	}
}
