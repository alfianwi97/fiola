package alf.security.fiola.internals.model.filesanitizer.single;

import com.fasterxml.jackson.annotation.JsonProperty;

import alf.security.fiola.internals.model.filesanitizer.FileByteSanitizingClientInput;

public class FileByteInputSanitizingRequest {
	@JsonProperty("file_client_input")
	private FileByteSanitizingClientInput fileClientInput;

	public FileByteSanitizingClientInput getFileClientInput() {
		return fileClientInput;
	}

	public void setFileClientInput(FileByteSanitizingClientInput fileClientInput) {
		this.fileClientInput = fileClientInput;
	}

}
