package alf.security.fiola.utility.properties;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import alf.security.fiola.internals.service.BaseService;
import alf.security.fiola.utility.code.returncode.ReturnCode;
import alf.security.fiola.utility.common.BaseController;
import alf.security.fiola.utility.common.BaseResponse;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;

@RestController
@Api(value = "Properties Reloader Controller")
public class PropertiesReloaderController extends BaseController {

	@Autowired
	PropertiesLoader propertiesLoader;

	BaseService baseService = new BaseService();

	@ApiOperation(value = "Reload Properties", notes = "Reload external properties files without restarting server.", response = BaseResponse.class)
	@RequestMapping(value = "reload-properties", method = RequestMethod.GET)
	public BaseResponse reloadProperties(Model model) throws Exception {
		transLog.info("Controller : reloadProperties");
		propertiesLoader.setAppProperties();
		propertiesLoader.setLogProperties();
		propertiesLoader.setDatasourceProperties();
		initLog();

		BaseResponse responseObject = new BaseResponse();
		responseObject.setReturnCode(ReturnCode.RC_SERVICE_RELOAD);
		baseService.setReturnMessage(responseObject, responseObject.getReturnCode());
		return responseObject;
	}

}
