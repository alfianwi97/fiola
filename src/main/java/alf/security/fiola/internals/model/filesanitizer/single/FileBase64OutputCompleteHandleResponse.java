package alf.security.fiola.internals.model.filesanitizer.single;

import com.fasterxml.jackson.annotation.JsonProperty;

import alf.security.fiola.internals.model.filesanitizer.FileBase64SanitizingClientOutput;

public class FileBase64OutputCompleteHandleResponse {
	@JsonProperty("file_client_output")
	private FileBase64SanitizingClientOutput fileClientOutput;

	public FileBase64SanitizingClientOutput getFileClientOutput() {
		return fileClientOutput;
	}

	public void setFileClientOutput(FileBase64SanitizingClientOutput fileClientOutput) {
		this.fileClientOutput = fileClientOutput;
	}
	
}
