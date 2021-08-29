package alf.security.fiola.internals.model.filevalidator;

import com.fasterxml.jackson.annotation.JsonProperty;

import alf.security.fiola.utility.common.BaseFileClientOutput;

public class FileByteValidatingClientOutput extends BaseFileClientOutput{
	@JsonProperty("file_name")
	private String fileName;
	private byte[] data;
	
	public byte[] getData() {
		return data;
	}
	public void setData(byte[] data) {
		this.data = data;
	}
	public String getFileName() {
		return fileName;
	}
	public void setFileName(String fileName) {
		this.fileName = fileName;
	}
	
	
}
