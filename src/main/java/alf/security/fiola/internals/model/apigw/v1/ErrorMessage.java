package alf.security.fiola.internals.model.apigw.v1;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ErrorMessage implements Serializable {
	
	private static final long serialVersionUID = -5949395779757002156L;
	
	@JsonProperty("indonesian")
	private String Indonesian;
	
	@JsonProperty("english")
	private String English;

	public String getIndonesian() {
		return Indonesian;
	}

	public void setIndonesian(String indonesian) {
		Indonesian = indonesian;
	}

	public String getEnglish() {
		return English;
	}

	public void setEnglish(String english) {
		English = english;
	}

	@Override
	public String toString() {
		return "ErrorMessage [Indonesian=" + Indonesian + ", English=" + English + "]";
	}

}
