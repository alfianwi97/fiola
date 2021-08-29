package alf.security.fiola.utility.common.interfaces;

public interface IBaseResponse {
		public int getHttpStatus();
		public void setHttpStatus(int httpStatus);
		public String getReturnCode();
		public void setReturnCode(String returnCode);
		public String getReturnMessageEnglish();
		public void setReturnMessageEnglish(String returnMessageEnglish);
		public String getReturnMessageIndonesia();
		public void setReturnMessageIndonesia(String returnMessageIndonesia);
}
