package alf.security.fiola.internals.model.apigw.v2;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class EaiOutputSchema<OutputSchema> extends EaiErrorSchema {

	private static final long serialVersionUID = -1810247038565055481L;

	@JsonProperty("OutputSchema")
	private OutputSchema outputSchema;

	public OutputSchema getOutputSchema() {
		return outputSchema;
	}

	public void setOutputSchema(OutputSchema outputSchema) {
		this.outputSchema = outputSchema;
	}

	@Override
	public String toString() {
		return "EaiOutputSchema [outputSchema=" + outputSchema + "]";
	}

}