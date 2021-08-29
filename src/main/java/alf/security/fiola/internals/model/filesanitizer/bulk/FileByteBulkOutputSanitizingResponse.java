package alf.security.fiola.internals.model.filesanitizer.bulk;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

import alf.security.fiola.internals.model.filesanitizer.FileByteSanitizingClientOutput;

public class FileByteBulkOutputSanitizingResponse {
	@JsonProperty("file_client_output")
	private List<FileByteSanitizingClientOutput> fileClientOutputList;

	public List<FileByteSanitizingClientOutput> getFileClientOutputList() {
		return fileClientOutputList;
	}

	public void setFileClientOutputList(List<FileByteSanitizingClientOutput> fileClientOutputList) {
		this.fileClientOutputList = fileClientOutputList;
	}

}
