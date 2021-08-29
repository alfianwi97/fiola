package alf.security.fiola.utility.misc;

import java.lang.reflect.Type;
import java.util.Date;

import org.springframework.stereotype.Component;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
@Component
public class JsonDateDeserializer implements JsonDeserializer<Date> {
	public Date deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) {
		Date d = new Date(json.getAsJsonPrimitive().getAsLong());
		return d;
	}
}
