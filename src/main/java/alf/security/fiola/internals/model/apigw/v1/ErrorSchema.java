package alf.security.fiola.internals.model.apigw.v1;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ErrorSchema implements Serializable {

	private static final long serialVersionUID = -5214044302778999420L;
	
	@JsonProperty("error_code")
	private String errorCode;
	
	@JsonProperty("error_message")
	private ErrorMessage errorMessage;

	public ErrorSchema() {
		super();
	}

	public String getErrorCode() {
		return errorCode;
	}

	public void setErrorCode(String errorCode) {
		this.errorCode = errorCode;
	}

	public ErrorMessage getErrorMessage() {
		return errorMessage;
	}

	public void setErrorMessage(ErrorMessage errorMessage) {
		this.errorMessage = errorMessage;
	}

	@Override
	public String toString() {
		return "ErrorSchema [errorCode=" + errorCode + ", errorMessage=" + errorMessage + "]";
	}

}
