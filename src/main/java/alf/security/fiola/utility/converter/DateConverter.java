package alf.security.fiola.utility.converter;

import java.util.HashMap;

import alf.security.fiola.utility.common.AppConstants;

public class DateConverter {
	private static HashMap<String, String> indonesianMonthFromOrder = new HashMap<String, String>() {
		private static final long serialVersionUID = 8044400104326028518L;
	{
	    put("01", "Januari");
	    put("02", "Febuari");
	    put("03", "Maret");
	    put("04", "April");
	    put("05", "Mei");
	    put("06", "Juni");
	    put("07", "Juli");
	    put("08", "Agustus");
	    put("09", "September");
	    put("10", "Oktober");
	    put("11", "November");
	    put("12", "Desember");
	}};
	
	public static String convertDateTo(String sourceDateFormat, String targetDateFormat, String date) throws Exception {
		String newDate = "";
		String[] dateParts = new String [3];
		
		date = date.substring(0, 10);
		
		switch(sourceDateFormat) {
		case AppConstants.FMT_DATE_DATEONLY_DDMMYYYY:	//	dd/mm/yyyy
			dateParts = date.split("/");
			break;
		case AppConstants.FMT_DATE_DATEONLY_DDMMYYYY_V2:	//	dd-mm-yyyy
			dateParts = date.split("-");
			break;
		case AppConstants.FMT_DATE_DATEONLY_DDMMYYYY_V4:	//	yyyy-mm-dd
			String[] tempDatePartsArr = date.split("-");
			dateParts[0]=tempDatePartsArr[2];
			dateParts[1]=tempDatePartsArr[1];
			dateParts[2]=tempDatePartsArr[0];
			break;
		default:
			throw new Exception("Date source format is unknown!");	
		}
		
		switch(targetDateFormat) {
		case AppConstants.FMT_DATE_DATEONLY_DDMMYYYY:	//	dd/mm/yyyy
			newDate = String.join("/", dateParts);
			break;
		case AppConstants.FMT_DATE_DATEONLY_DDMMYYYY_V2:	//	dd-mm-yyyy
			newDate = String.join("-", dateParts);
			break;
		case AppConstants.FMT_DATE_DATEONLY_DDMMYYYY_V3:	//	dd Month yyyy
			String month = indonesianMonthFromOrder.get(dateParts[1]);
			newDate = String.format("%s %s %s", dateParts[0], month, dateParts[2]);
			break;
		case AppConstants.FMT_DATE_DATEONLY_DDMMYYYY_V4:	//	yyyy-mm-dd
			newDate = String.format("%s-%s-%s", dateParts[2], dateParts[1], dateParts[0]);
			break;
		default:
			throw new Exception("Date target format is unknown!");	
		}
		
		return newDate;
	}
}
