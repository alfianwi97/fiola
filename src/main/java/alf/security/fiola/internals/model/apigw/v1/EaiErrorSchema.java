package alf.security.fiola.internals.model.apigw.v1;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class EaiErrorSchema implements Serializable {
	private static final long serialVersionUID = 4474072973596170026L;

	public EaiErrorSchema() {
		this.errorSchema = new ErrorSchema();
	}
	
	@JsonProperty("error_schema")
	private ErrorSchema errorSchema;

	public ErrorSchema getErrorSchema() {
		return errorSchema;
	}

	public void setErrorSchema(ErrorSchema errorSchema) {
		this.errorSchema = errorSchema;
	}

	@Override
	public String toString() {
		return "EaiErrorSchema [errorSchema=" + errorSchema + "]";
	}

}
