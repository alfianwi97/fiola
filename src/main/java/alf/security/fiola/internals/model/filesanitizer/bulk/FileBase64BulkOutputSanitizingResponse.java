package alf.security.fiola.internals.model.filesanitizer.bulk;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

import alf.security.fiola.internals.model.filesanitizer.FileBase64SanitizingClientOutput;

public class FileBase64BulkOutputSanitizingResponse {
	@JsonProperty("file_client_output_list")
	private List<FileBase64SanitizingClientOutput> fileClientOutputList;

	public List<FileBase64SanitizingClientOutput> getFileClientOutputList() {
		return fileClientOutputList;
	}

	public void setFileClientOutputList(List<FileBase64SanitizingClientOutput> fileClientOutputList) {
		this.fileClientOutputList = fileClientOutputList;
	}
	
}
