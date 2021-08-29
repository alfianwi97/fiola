package alf.security.fiola.utility.common;

import javax.annotation.PostConstruct;

import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import alf.security.fiola.utility.code.returncode.ReturnCodeMessageMapEnglish;
import alf.security.fiola.utility.code.returncode.ReturnCodeMessageMapIndonesia;
import alf.security.fiola.utility.logging.LogInitializer;

@Component
public class BaseComponent {

	@Autowired
	LogInitializer log;

	protected static Logger transLog;

	@PostConstruct
	public void initLog() {
		BaseComponent.transLog = log.transLogging();
	}

	public Logger getTransLog() {
		return transLog;
	}

	public void setReturnMessage(BaseResponse responseObject, String returnCode) {
		responseObject.setHttpStatus(200);
		responseObject.setReturnMessageEnglish(ReturnCodeMessageMapEnglish.getMessage(returnCode));
		responseObject.setReturnMessageIndonesia(ReturnCodeMessageMapIndonesia.getMessage(returnCode));
	}

	/**
	 * @notes Response with custom message
	 */
	public void setReturnMessage(BaseResponse responseObject, String returnCode, boolean dummyOverloading,
			String... invalidEntry) {
		if (null != invalidEntry && invalidEntry.length > 0) {
			if (!"".equalsIgnoreCase(invalidEntry[0])) {
				responseObject.setHttpStatus(200);
				responseObject
						.setReturnMessageEnglish(ReturnCodeMessageMapEnglish.getMessage(returnCode) + " : " + invalidEntry[0]);
				responseObject.setReturnMessageIndonesia(
						ReturnCodeMessageMapIndonesia.getMessage(returnCode) + " : " + invalidEntry[0]);
			} else {
				setReturnMessage(responseObject, returnCode);
			}
		} else {
			setReturnMessage(responseObject, returnCode);
		}
	}

	/**
	 * @notes messageEnglish and messageIndonesia must be filled
	 */
	public void setReturnMessage(BaseResponse responseObject, String messageEnglish, String messageIndonesia) {
		responseObject.setHttpStatus(200);
		responseObject.setReturnMessageEnglish(messageEnglish);
		responseObject.setReturnMessageIndonesia(messageIndonesia);
	}

}
