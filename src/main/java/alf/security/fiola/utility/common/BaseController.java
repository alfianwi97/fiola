package alf.security.fiola.utility.common;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BaseController extends BaseComponent {
	@Autowired
	protected HttpServletRequest request;

	@Autowired
	protected HttpServletResponse response;

}
