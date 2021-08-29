package alf.security.fiola.utility.sanitizer;

import alf.security.fiola.utility.code.diagnostic.Diagnostic;
import lombok.Data;

@Data
public class SanitizerResult {
	private byte[] sanitizedData;
	private Diagnostic diagnostic;
	
	public SanitizerResult() {
		this.diagnostic = new Diagnostic();
	}
}
