package alf.security.fiola.utility.validator.file;

import alf.security.fiola.utility.code.diagnostic.Diagnostic;
import lombok.Data;

@Data
public class ValidatorResult {
	private boolean isSafe;
	private Diagnostic diagnostic;
	
	public ValidatorResult() {
		this.diagnostic = new Diagnostic();
	}
}
