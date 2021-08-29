package alf.security.fiola.internals.model.filevalidator;

public class FileByteValidatingClientInput extends BaseFileValidatingClientInput{
	private byte[] data;
	
	public byte[] getData() {
		return data;
	}
	public void setData(byte[] data) {
		this.data = data;
	}
}
