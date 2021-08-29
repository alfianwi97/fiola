package alf.security.fiola.internals.model.filecompletehandle;

import alf.security.fiola.utility.common.BaseFileClientInput;
import lombok.Data;

@Data
public class FileBase64CompleteHandleClientInput extends BaseFileClientInput {
	private String data;
}
