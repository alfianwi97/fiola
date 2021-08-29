package alf.security.fiola.internals.model.filevalidator.single;

import com.fasterxml.jackson.annotation.JsonProperty;

import alf.security.fiola.internals.model.filevalidator.FileByteValidatingClientInput;

public class FileByteInputValidatingRequest {
	@JsonProperty("file_client_input")
	private FileByteValidatingClientInput fileClientInput;

	public FileByteValidatingClientInput getFileClientInput() {
		return fileClientInput;
	}

	public void setFileClientInput(FileByteValidatingClientInput fileClientInput) {
		this.fileClientInput = fileClientInput;
	}

}
