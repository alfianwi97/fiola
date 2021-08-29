package alf.security.fiola.utility.validator;

import java.math.BigDecimal;

public class NumberValidator {
	public static boolean isDecimal(String number) {
		try {
	        new BigDecimal(number);
	    } catch (NumberFormatException | NullPointerException nfe) {
	        return false;
	    }
	    return true;
	}
	
	public static boolean isPositiveDecimal(String number) {
		BigDecimal bd = null;
		try {
			bd = new BigDecimal(number);
	    } catch (NumberFormatException | NullPointerException nfe) {
	        return false;
	    }
		
		if(bd.compareTo(BigDecimal.ZERO) < 0) return false;
	    return true;
	}
}
