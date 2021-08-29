package alf.security.fiola.internals.model.filesanitizer.bulk;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

import alf.security.fiola.internals.model.filesanitizer.single.FileByteInputSanitizingRequest;

public class FileByteBulkInputSanitizingRequest {
	@JsonProperty("bulk_data")
	private List<FileByteInputSanitizingRequest> bulkData;

	public List<FileByteInputSanitizingRequest> getBulkData() {
		return bulkData;
	}

	public void setBulkData(List<FileByteInputSanitizingRequest> bulkData) {
		this.bulkData = bulkData;
	}

	@Override
	public String toString() {
		return "FileBase64BulkOutputSanitizingResponse [bulkData=" + bulkData + "]";
	}
}
