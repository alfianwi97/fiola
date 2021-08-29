package alf.security.fiola.internals.model.filevalidator;

import java.util.List;

public interface IFileConstraintValidationRequest {
	public List<String> getExpectedFileFormats();
	public void setExpectedFileFormats(List<String> expectedFileFormat);
	public FileConstraint getFileConstraint();
}
