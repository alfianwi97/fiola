package alf.security.fiola.utility.common;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

import alf.security.fiola.internals.model.filevalidator.FileConstraint;
import alf.security.fiola.internals.model.filevalidator.IFileConstraintValidationRequest;
import lombok.Data;

@Data
public abstract class BaseFileClientInput implements IFileConstraintValidationRequest{
	@JsonProperty("file_name")
	private String fileName;
	@JsonProperty("expected_file_formats")
	private List<String> expectedFileFormats;
	@JsonProperty("file_constraint")
	private FileConstraint fileConstraint;
	@Override
	public String toString() {
		return "BaseFileClientInput [fileName=" + fileName + ", expectedFileFormats=" + expectedFileFormats
				+ ", fileConstraint=" + fileConstraint + "]";
	}
	
	
}
