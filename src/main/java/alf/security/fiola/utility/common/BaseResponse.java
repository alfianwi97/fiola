package alf.security.fiola.utility.common;

import java.io.Serializable;

import alf.security.fiola.utility.code.returncode.ReturnCodeMessageMapEnglish;
import alf.security.fiola.utility.code.returncode.ReturnCodeMessageMapIndonesia;
import alf.security.fiola.utility.common.interfaces.IBaseResponse;

public class BaseResponse implements Serializable, IBaseResponse {

	private static final long serialVersionUID = 2156282653464125017L;

	private int httpStatus;
	private String returnCode;
	private String returnMessageEnglish;
	private String returnMessageIndonesia;

	public BaseResponse() {
		super();
	}

	public BaseResponse(String returnCode) {
		this.httpStatus = 200;
		this.returnCode = returnCode;
		this.returnMessageEnglish = ReturnCodeMessageMapEnglish.getMessage(returnCode);
		this.returnMessageIndonesia = ReturnCodeMessageMapIndonesia.getMessage(returnCode);
	}

	public int getHttpStatus() {
		return httpStatus;
	}

	public void setHttpStatus(int httpStatus) {
		this.httpStatus = httpStatus;
	}

	public String getReturnCode() {
		return returnCode;
	}

	public void setReturnCode(String returnCode) {
		this.returnCode = returnCode;
	}

	public String getReturnMessageEnglish() {
		return returnMessageEnglish;
	}

	public void setReturnMessageEnglish(String returnMessageEnglish) {
		this.returnMessageEnglish = returnMessageEnglish;
	}

	public String getReturnMessageIndonesia() {
		return returnMessageIndonesia;
	}

	public void setReturnMessageIndonesia(String returnMessageIndonesia) {
		this.returnMessageIndonesia = returnMessageIndonesia;
	}

	@Override
	public String toString() {
		return "BaseResponse [httpStatus=" + httpStatus + ", returnCode=" + returnCode + ", returnMessageEnglish="
				+ returnMessageEnglish + ", returnMessageIndonesia=" + returnMessageIndonesia + "]";
	}
}
