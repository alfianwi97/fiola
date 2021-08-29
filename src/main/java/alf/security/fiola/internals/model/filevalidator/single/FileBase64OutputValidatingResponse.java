package alf.security.fiola.internals.model.filevalidator.single;

import com.fasterxml.jackson.annotation.JsonProperty;

import alf.security.fiola.internals.model.filevalidator.FileBase64ValidatingClientOutput;
import lombok.Data;

@Data
public class FileBase64OutputValidatingResponse {
	@JsonProperty("file_client_output")
	private FileBase64ValidatingClientOutput fileClientOutput;
}
