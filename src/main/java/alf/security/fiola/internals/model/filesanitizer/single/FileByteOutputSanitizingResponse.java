package alf.security.fiola.internals.model.filesanitizer.single;

import com.fasterxml.jackson.annotation.JsonProperty;

import alf.security.fiola.internals.model.filesanitizer.FileByteSanitizingClientOutput;

public class FileByteOutputSanitizingResponse {
	@JsonProperty("file_client_output")
	private FileByteSanitizingClientOutput fileClientOutput;

	public FileByteSanitizingClientOutput getFileClientOutput() {
		return fileClientOutput;
	}

	public void setFileClientOutput(FileByteSanitizingClientOutput fileClientOutput) {
		this.fileClientOutput = fileClientOutput;
	}

	
}
