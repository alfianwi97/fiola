package alf.security.fiola.internals.service;

import org.springframework.stereotype.Service;

import alf.security.fiola.internals.model.apigw.v1.ErrorMessage;
import alf.security.fiola.internals.model.apigw.v1.ErrorSchema;
import alf.security.fiola.internals.model.apigw.v1.IEaiOutputSchema;
import alf.security.fiola.utility.code.returncode.ReturnCode;
import alf.security.fiola.utility.code.returncode.ReturnCodeMessageMapEnglish;
import alf.security.fiola.utility.code.returncode.ReturnCodeMessageMapIndonesia;
import alf.security.fiola.utility.common.BaseComponent;

@Service
public class BaseService extends BaseComponent {

//	@Autowired
//	protected RestTemplate restTemplate;
//
//	@Autowired
//	@Qualifier("sslRestTemplate")
//	protected RestTemplate sslRestTemplate;




	public void setReturnMessage(IEaiOutputSchema<?> responseObject, String errorCode) {
		if(errorCode.equals(ReturnCode.RC_SERVICE_SUCCESS)) return;

		ErrorSchema errScm = new ErrorSchema();
		ErrorMessage errMsg = new ErrorMessage();
		errMsg.setEnglish(ReturnCodeMessageMapEnglish.getMessage(errorCode));
		errMsg.setIndonesian(ReturnCodeMessageMapIndonesia.getMessage(errorCode));
		
		errScm.setErrorCode(errorCode);
		errScm.setErrorMessage(errMsg);
		responseObject.setErrorSchema(errScm);
	}
}
