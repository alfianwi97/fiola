package alf.security.fiola.internals.model.filevalidator;

import com.fasterxml.jackson.annotation.JsonProperty;

import alf.security.fiola.utility.common.BaseFileClientOutput;
import lombok.Data;

@Data
public class FileBase64ValidatingClientOutput extends BaseFileClientOutput{
	@JsonProperty("file_name")
	private String fileName;
	private String data;
}
