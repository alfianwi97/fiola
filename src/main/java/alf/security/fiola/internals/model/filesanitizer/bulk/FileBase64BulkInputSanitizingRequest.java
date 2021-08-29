package alf.security.fiola.internals.model.filesanitizer.bulk;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

import alf.security.fiola.internals.model.filesanitizer.FileBase64ClientInput;

public class FileBase64BulkInputSanitizingRequest {
	@JsonProperty("file_client_input_list")
	private List<FileBase64ClientInput> fileClientInputList;

	public List<FileBase64ClientInput> getFileClientInputList() {
		return fileClientInputList;
	}

	public void setFileClientInputList(List<FileBase64ClientInput> fileClientInputList) {
		this.fileClientInputList = fileClientInputList;
	}


}
