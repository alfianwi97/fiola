package alf.security.fiola.utility.validator;

import org.apache.commons.lang.StringUtils;

import alf.security.fiola.utility.common.BaseComponent;

public class CommonValidator extends BaseComponent{
			
	public static boolean isDataAndLengthFit(String data, boolean mandatory, int maxLength) {
		if(mandatory && StringUtils.isBlank(data)) return false;
		if(!StringUtils.isBlank(data) && data.length() > maxLength) return false;
		return true;
	}
	
//	public static boolean isDataValid(String checkedData, List<Map<String,String>> mtData, String checkedDataName, boolean mandatoryValueCheck) {
//		if(mandatoryValueCheck && StringUtils.isBlank(checkedData)) {
//			gLog.info("Invalid {}, null data!", checkedDataName);
//			return false;
//		}
//		if(StringUtils.isBlank(checkedData)) return true;
//		boolean found = false;
//		for (Map<String, String> data : mtData) {
//			if(checkedData.equals(data.get("keyCode"))) {
//				found = true;
//				break;
//			}
//		}
//		if(!found) {
//			gLog.info("Invalid {}, no code match for : {}", checkedDataName, checkedData);
//			return false;
//		}
//		return true;
//	}
//	
	
//	public static boolean isDataValidWithEtc(String checkedData, List<Map<String,String>> mtData, String checkedDataName, String etcData, int maxEtcDataLength, boolean mandatoryValueCheck) {
//		if(!isDataValid(checkedData, mtData, checkedDataName, mandatoryValueCheck))
//			return false;
//		
//		if(!mandatoryValueCheck) {
//			if(StringUtils.isBlank(checkedData)) return true;
//		}
//		else if(StringUtils.isBlank(checkedData)) {
//			gLog.info("Invalid other {}, null data!", checkedDataName);
//			return false;
//		}
//		
//		if(checkedData.equals("ETC")) {
//			if(!isDataAndLengthFit(etcData, mandatoryValueCheck, maxEtcDataLength)) {
//				gLog.info("Invalid other {}!",checkedDataName);
//				return false;
//			}
//		}
//		return true;
//	}
		
//	public static boolean isMasterDataValid(String checkedData, String groupCd, String checkedDataName, boolean mandatoryValueCheck) throws Exception {
//		if(mandatoryValueCheck && StringUtils.isBlank(checkedData)) {
//			gLog.info("Invalid {}, null data!", checkedDataName);
//			return false;
//		}
//		if(StringUtils.isBlank(checkedData)) return true;
//		
//		String additionalCondition = String.format(" AND param_cd = '%s'", checkedData);
//		List<Map<String,String>> collTypeListMap = MtnbDataObjectDAO.getListParam(groupCd,null,additionalCondition,null);
//		if(collTypeListMap == null || collTypeListMap.size() == 0) {
//			gLog.info("Invalid {}, no record in master data!", checkedDataName);
//			return false;
//		}
//		return true;
//	}
	
//	public static boolean isMasterDataValidWithEtc(String checkedData, String paramCd, String checkedDataName, boolean mandatoryValueCheck, String etcData, int maxEtcDataLength) throws Exception {
//		if(!isMasterDataValid(checkedData, paramCd, checkedDataName, mandatoryValueCheck))
//			return false;
//		
//		if(!mandatoryValueCheck) {
//			if(StringUtils.isBlank(checkedData)) return true;
//		}
//		else if(StringUtils.isBlank(checkedData)) {
//			gLog.info("Invalid other {}, null data!", checkedDataName);
//			return false;
//		}
//		
//		if(checkedData.equals("ETC")) {
//			if(!isDataAndLengthFit(etcData, mandatoryValueCheck, maxEtcDataLength)) {
//				gLog.info("Invalid other {}!",checkedDataName);
//				return false;
//			}
//		}
//		return true;
//	}
}
