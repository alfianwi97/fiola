package alf.security.fiola.internals.model.filesanitizer;

import alf.security.fiola.utility.common.BaseFileClientInput;

public class FileByteSanitizingClientInput extends BaseFileClientInput{
	private byte[] data;

	public byte[] getData() {
		return data;
	}

	public void setData(byte[] data) {
		this.data = data;
	}

}
