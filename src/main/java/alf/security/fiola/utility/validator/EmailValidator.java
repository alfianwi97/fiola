package alf.security.fiola.utility.validator;

import java.util.regex.Pattern;

public class EmailValidator {

	public static boolean isEmailValid(String email) {
		
		Pattern pattern = Pattern.compile("^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,6}$", Pattern.CASE_INSENSITIVE);
		if (pattern.matcher(email).matches()) {
			return true;
		}
		
		return false;
	}
}
