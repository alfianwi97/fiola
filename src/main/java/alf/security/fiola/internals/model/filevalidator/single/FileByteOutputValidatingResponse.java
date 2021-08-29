package alf.security.fiola.internals.model.filevalidator.single;

import com.fasterxml.jackson.annotation.JsonProperty;

import alf.security.fiola.internals.model.filevalidator.FileByteValidatingClientOutput;

public class FileByteOutputValidatingResponse {
	@JsonProperty("file_client_output")
	private FileByteValidatingClientOutput fileClientOutput;

	public FileByteValidatingClientOutput getFileClientOutput() {
		return fileClientOutput;
	}

	public void setFileClientOutput(FileByteValidatingClientOutput fileClientOutput) {
		this.fileClientOutput = fileClientOutput;
	}

	
}
