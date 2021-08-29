package alf.security.fiola.utility.validator;

import java.time.LocalDate;
import java.time.Period;
import java.time.format.DateTimeFormatter;
import java.util.regex.Pattern;

import alf.security.fiola.utility.common.AppConstants;

public class DateValidator {
	public static boolean isDateFormatValid(String dateFormat, String date) throws Exception {
		Pattern dateFormatPattern = null;
		
		switch(dateFormat) {
		case AppConstants.FMT_DATE_DATEONLY_DDMMYYYY:	//	dd/mm/yyyy
			dateFormatPattern = Pattern.compile("[0-9]{2}\\/[0-9]{2}\\/[0-9]{4}");
			break;
		case AppConstants.FMT_DATE_DATEONLY_DDMMYYYY_V2:	//	dd-mm-yyyy
			dateFormatPattern = Pattern.compile("[0-9]{2}-[0-9]{2}-[0-9]{4}");
			break;
		case AppConstants.FMT_DATE_DATEONLY_DDMMYYYY_V3:	//	dd Month yyyy
			dateFormatPattern = Pattern.compile("[0-9]{2} [a-zA-Z]+ [0-9]{4}");
			break;
		default:
			throw new Exception("Date format is unknown!");	
		}
		
		if(dateFormatPattern.matcher(date).matches()) return true;
		return false;
	}
	
	public static boolean isDateInFuture(String dateFormat, String date) {
		LocalDate localDate = LocalDate.parse(date, DateTimeFormatter.ofPattern(dateFormat));
		Period period = Period.between(localDate, LocalDate.now());
		if(period.isNegative()) return true;
		return false;
	}
	
	public static boolean isDateInPast(String dateFormat, String date) {
		LocalDate localDate = LocalDate.parse(date, DateTimeFormatter.ofPattern(dateFormat));
		Period period = Period.between(localDate, LocalDate.now());
		if(period.isNegative()) return false;
		return true;
	}
	
	public static boolean isDateBetween(String dateFormat, String date, String dateFrom, String dateTo) {
		LocalDate localDate = LocalDate.parse(date, DateTimeFormatter.ofPattern(dateFormat));
		LocalDate localDateFrom = LocalDate.parse(dateFrom, DateTimeFormatter.ofPattern(dateFormat));
		LocalDate localDateTo = LocalDate.parse(dateTo, DateTimeFormatter.ofPattern(dateFormat));
		
		Period period = Period.between(localDateFrom, localDate);
		Period period2 = Period.between(localDate, localDateTo);
		if(period.isNegative() || period2.isNegative()) return false;
		return true;
	}
	
	public static boolean isTodayBetween(String dateFormat, String dateFrom, String dateTo) {
		LocalDate localDate = LocalDate.now();
		LocalDate localDateFrom = LocalDate.parse(dateFrom, DateTimeFormatter.ofPattern(dateFormat));
		LocalDate localDateTo = LocalDate.parse(dateTo, DateTimeFormatter.ofPattern(dateFormat));
		
		Period period = Period.between(localDateFrom, localDate);
		Period period2 = Period.between(localDate, localDateTo);
		if(period.isNegative() || period2.isNegative()) return false;
		return true;
	}
}
