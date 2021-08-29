package alf.security.fiola.internals.model.filecompletehandle;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;

@Data
public class FileBase64CompleteHandleRequest {
	@JsonProperty("file_client_input")
	private FileBase64CompleteHandleClientInput fileClientInput;
}
