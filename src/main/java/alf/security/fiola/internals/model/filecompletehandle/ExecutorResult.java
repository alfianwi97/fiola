package alf.security.fiola.internals.model.filecompletehandle;

import alf.security.fiola.utility.code.diagnostic.Diagnostic;
import lombok.Data;

@Data
public class ExecutorResult {
	private byte[] data;
	private Diagnostic diagnostic;
	
	public ExecutorResult() {
		this.diagnostic = new Diagnostic();
	}
}
