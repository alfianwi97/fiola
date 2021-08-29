package alf.security.fiola.utility.exception;

import java.net.SocketTimeoutException;

import javax.annotation.PostConstruct;

import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import alf.security.fiola.internals.service.BaseService;
import alf.security.fiola.utility.code.returncode.ReturnCode;
import alf.security.fiola.utility.common.BaseResponse;

@ControllerAdvice
public class AppExceptionHandler extends ResponseEntityExceptionHandler {

	@Autowired
	BaseService baseService;

	Logger gLog;

	@PostConstruct
	public void init() {
		gLog = baseService.getTransLog();
	}

	/**
	 * @notes Handling mismatch argument type
	 **/
	@ExceptionHandler({ MethodArgumentTypeMismatchException.class })
	public BaseResponse handleMethodArgumentTypeMismatch(MethodArgumentTypeMismatchException ex, WebRequest request) {
		String error = ex.getName() + " should be of type " + ex.getRequiredType().getName();
		gLog.error("Error : {}", error);
		return new BaseResponse(ReturnCode.RC_SERVICE_BAD_INPUT);
	}

	/**
	 * @notes Handling 404 Not Found
	 **/
	@Override
	protected ResponseEntity<Object> handleNoHandlerFoundException(NoHandlerFoundException ex, HttpHeaders headers,
			HttpStatus status, WebRequest request) {
		String error = "No handler found for " + ex.getHttpMethod() + " " + ex.getRequestURL();
		gLog.error("Error : {}", error);
		return new ResponseEntity<Object>(new BaseResponse(ReturnCode.RC_SERVICE_NOT_FOUND), new HttpHeaders(),
				HttpStatus.NOT_FOUND);
	}

	/**
	 * @notes Handling unsupported request method
	 **/
	@Override
	protected ResponseEntity<Object> handleHttpRequestMethodNotSupported(HttpRequestMethodNotSupportedException ex,
			HttpHeaders headers, HttpStatus status, WebRequest request) {
		StringBuilder builder = new StringBuilder();
		builder.append(ex.getMethod());
		builder.append(" method is not supported for this request. Supported methods are ");
		ex.getSupportedHttpMethods().forEach(t -> builder.append(t + " "));
		gLog.error("Error : {}", builder);
		return new ResponseEntity<Object>(new BaseResponse(ReturnCode.RC_SERVICE_METHOD_NOT_ALLOWED), new HttpHeaders(),
				HttpStatus.METHOD_NOT_ALLOWED);
	}

	/**
	 * @notes Handling unsupported media type
	 **/
	@Override
	protected ResponseEntity<Object> handleHttpMediaTypeNotSupported(HttpMediaTypeNotSupportedException ex,
			HttpHeaders headers, HttpStatus status, WebRequest request) {
		StringBuilder builder = new StringBuilder();
		builder.append(ex.getContentType());
		builder.append(" media type is not supported. Supported media types are ");
		ex.getSupportedMediaTypes().forEach(t -> builder.append(t + ", "));
		gLog.error("Error : {}", builder);
		return new ResponseEntity<Object>(new BaseResponse(ReturnCode.RC_SERVICE_UNSUPPORTED_MEDIA_TYPE),
				new HttpHeaders(), HttpStatus.UNSUPPORTED_MEDIA_TYPE);
	}

	/**
	 * @notes Handling missing params
	 **/
	@Override
	protected ResponseEntity<Object> handleMissingServletRequestParameter(MissingServletRequestParameterException ex,
			HttpHeaders headers, HttpStatus status, WebRequest request) {
		return new ResponseEntity<Object>(new BaseResponse(ReturnCode.RC_SERVICE_BAD_REQUEST), new HttpHeaders(),
				HttpStatus.BAD_REQUEST);
	}

	/**
	 * @notes time out config
	 */
	@ExceptionHandler({ ResourceAccessException.class })
	public ResponseEntity<Object> handleResourceAccess(Exception ex, WebRequest request) {
		return new ResponseEntity<Object>(new BaseResponse(ReturnCode.RC_SERVICE_TIMEOUT), new HttpHeaders(),
				HttpStatus.REQUEST_TIMEOUT);
	}

	/**
	 * @notes time out config
	 */
	@ExceptionHandler({ SocketTimeoutException.class })
	public ResponseEntity<Object> handleTimeout(Exception ex, WebRequest request) {
		return new ResponseEntity<Object>(new BaseResponse(ReturnCode.RC_SERVICE_TIMEOUT), new HttpHeaders(),
				HttpStatus.REQUEST_TIMEOUT);
	}

	/**
	 * @notes Handling all exception
	 **/
	@ExceptionHandler({ Exception.class })
	public ResponseEntity<Object> handleAll(Exception ex, WebRequest request) {
		return new ResponseEntity<Object>(new BaseResponse(ReturnCode.RC_SERVICE_GENERAL_ERROR), new HttpHeaders(),
				HttpStatus.INTERNAL_SERVER_ERROR);
	}
}
