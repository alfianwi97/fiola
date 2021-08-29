package alf.security.fiola.internals.model.filesanitizer;

import alf.security.fiola.utility.common.BaseFileClientInput;

public class FileBase64ClientInput extends BaseFileClientInput{
	private String data;
	
	public String getData() {
		return data;
	}
	public void setData(String data) {
		this.data = data;
	}
}
