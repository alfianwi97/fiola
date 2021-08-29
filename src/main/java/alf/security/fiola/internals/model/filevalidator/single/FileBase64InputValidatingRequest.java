package alf.security.fiola.internals.model.filevalidator.single;

import com.fasterxml.jackson.annotation.JsonProperty;

import alf.security.fiola.internals.model.filevalidator.FileBase64ValidatingClientInput;

public class FileBase64InputValidatingRequest {
	@JsonProperty("file_client_input")
	private FileBase64ValidatingClientInput	fileClientInput;

	public FileBase64ValidatingClientInput getFileClientInput() {
		return fileClientInput;
	}

	public void setFileClientInput(FileBase64ValidatingClientInput fileClientInput) {
		this.fileClientInput = fileClientInput;
	}

	
}
