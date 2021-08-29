package alf.security.fiola.internals.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import alf.security.fiola.internals.model.apigw.v1.EaiOutputSchema;
import alf.security.fiola.internals.model.filecompletehandle.FileBase64CompleteHandleRequest;
import alf.security.fiola.internals.model.filesanitizer.single.FileBase64OutputCompleteHandleResponse;
import alf.security.fiola.internals.service.FileCompleteHandleService;
import alf.security.fiola.utility.common.BaseController;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;

@RestController
@RequestMapping(value = "complete")
@Api(value="Complete Handler")
public class FileCompleteHandleController extends BaseController {

	@Autowired
	private FileCompleteHandleService fileCompleteHandleService;
	
	
	@ApiOperation(value = "Handle Base64 File to Base64", notes = "Handle file from base64 input to base64 output", response = FileBase64OutputCompleteHandleResponse.class)
	@PostMapping(value = "file/base64-to-base64")
	public EaiOutputSchema<FileBase64OutputCompleteHandleResponse> handleBase64FileToBase64(HttpServletRequest httpServletRequest, @RequestBody FileBase64CompleteHandleRequest request) {
		transLog.info("======== Controller :: completeHandleBase64FileToBase64");
		
		EaiOutputSchema<FileBase64OutputCompleteHandleResponse> responseObject = null;
//		try {
			responseObject = fileCompleteHandleService.handleFileBase64ContentToBase64(request);
//		} catch (Exception e) {
//			e.printStackTrace();
//		}
		return responseObject;
	}
	
}
