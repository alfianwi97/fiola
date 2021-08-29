package alf.security.fiola.internals.model.filesanitizer;

import com.fasterxml.jackson.annotation.JsonProperty;

import alf.security.fiola.utility.common.BaseFileClientOutput;

public class FileBase64SanitizingClientOutput extends BaseFileClientOutput{
	@JsonProperty("file_name")
	private String fileName;
	private String data;
	
	public String getData() {
		return data;
	}
	public void setData(String data) {
		this.data = data;
	}
	public String getFileName() {
		return fileName;
	}
	public void setFileName(String fileName) {
		this.fileName = fileName;
	}
	
	
}
