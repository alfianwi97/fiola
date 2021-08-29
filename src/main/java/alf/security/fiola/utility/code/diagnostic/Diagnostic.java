package alf.security.fiola.utility.code.diagnostic;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;

@Data
public class Diagnostic {
	@JsonProperty("detection_code")
	private String detectionCode;
	private String message;
}
