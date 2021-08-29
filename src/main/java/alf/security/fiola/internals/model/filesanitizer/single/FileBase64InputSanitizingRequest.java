package alf.security.fiola.internals.model.filesanitizer.single;

import com.fasterxml.jackson.annotation.JsonProperty;

import alf.security.fiola.internals.model.filesanitizer.FileBase64ClientInput;

public class FileBase64InputSanitizingRequest {
	@JsonProperty("file_client_input")
	private FileBase64ClientInput	fileClientInput;

	public FileBase64ClientInput getFileClientInput() {
		return fileClientInput;
	}

	public void setFileClientInput(FileBase64ClientInput fileClientInput) {
		this.fileClientInput = fileClientInput;
	}

	@Override
	public String toString() {
		return "FileBase64InputSanitizingRequest [fileClientInput=" + fileClientInput + "]";
	}

}
