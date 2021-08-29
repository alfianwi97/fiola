package alf.security.fiola.config.auth;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;

import alf.security.fiola.internals.service.BaseService;
import alf.security.fiola.utility.common.BaseComponent;
import alf.security.fiola.utility.properties.PropertiesConstants;

@Controller
public class AppAuthFilter extends BaseComponent implements Filter {
	Logger gLog = null;

	@Autowired
	private BaseService baseService;
	
	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		gLog = baseService.getTransLog();
	}

	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) servletRequest;
		HttpServletResponse response = (HttpServletResponse) servletResponse;
		
		String uri = request.getRequestURI();
		boolean isInvalidAccess = false;
		boolean isForbidden = false;
		boolean isAllowedAnonAccess = false;
		
//		String authSessionId = request.getHeader("Authorization");
		String appSecretKey = request.getHeader("app-secret-key");
		
		isAllowedAnonAccess = isAllowedAnonymousURL(request);
		
		if(appSecretKey == null || !appSecretKey.equals(PropertiesConstants.appSecretKeyHash)) {
			isInvalidAccess = true;
			gLog.info("app-secret-key is empty or not match: "+appSecretKey);
		}

		if(!isInvalidAccess) {
			long requestSizeInKb = request.getContentLengthLong()/1024;
			if(requestSizeInKb > PropertiesConstants.requestBodyMaxSizeInKb) {
				gLog.info("Content length is more than {} KB : {}", PropertiesConstants.requestBodyMaxSizeInKb, request.getContentLengthLong());
				isForbidden = true;
			}

			gLog.info("Request Method : {} ", request.getMethod());
			gLog.info("URI : {} ", uri);
			if(!isAllowedAnonAccess) gLog.info("Content length : {} KB", requestSizeInKb);
		}
				
		if (isInvalidAccess && !isAllowedAnonAccess) {
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//			request.getRequestDispatcher("/unauthorized").forward(null, response);
			response.sendRedirect(request.getContextPath() + "/unauthorized");
			gLog.info("Unauthorized access attempt from IP : {}, PC Name : {}", request.getRemoteAddr(), request.getRemoteHost());
		} else if (isForbidden && !isAllowedAnonAccess){
			response.setStatus(HttpServletResponse.SC_FORBIDDEN);
			response.sendRedirect(request.getContextPath() + "/forbidden");
			gLog.info("Forbidden access attempt from IP : {}, PC Name : {}", request.getRemoteAddr(), request.getRemoteHost());
		} else {
			if(!isAllowedAnonAccess) gLog.info("Content size : "+request.getContentLengthLong());
			response.setStatus(HttpServletResponse.SC_OK);
			chain.doFilter(servletRequest, servletResponse);
		}
	}

	public void destroy() {}

	// Added by Alfian
//	public UserDetailResponse getUserDetail(String loginSessionId) {
//		UserDetailResponse response = new UserDetailResponse();
//		UserDetailResponse userDetail = null;
//		try {
//			if (loginSessionId != null && !"".equals(loginSessionId)) {
//				response = uidmService.getUserDetailByLoginSession(loginSessionId);
//				if (response.getUserDetail().getUserId() != null) {
//					userDetail = response;
//				}
//			}
//		} catch (Exception e) {
//			gLog.info("Error getting user detail by loginSessionId, " + e);
//		}
//		return userDetail;
//	}

	private boolean isAllowedAnonymousURL(HttpServletRequest request) {
		boolean retVal = false;
		String uri = request.getRequestURI();

		List<String> allowedAnonymousURL = new ArrayList<String>();
		allowedAnonymousURL.add("/fiola-svc-int/index");
		allowedAnonymousURL.add("/fiola-svc-int/unauthorized");
		allowedAnonymousURL.add("/fiola-svc-int/forbidden");
		allowedAnonymousURL.add("/fiola-svc-int/reload-properties");
		allowedAnonymousURL.add("/fiola-svc-int/swagger-ui.html");
		allowedAnonymousURL.add("/fiola-svc-int/v2/api-docs");
//		allowedAnonymousURL.add("/fiola-svc-int/webjars");//?
//		allowedAnonymousURL.add("/fiola-svc-int/images");//?
//		allowedAnonymousURL.add("/fiola-svc-int/configuration");//?
		allowedAnonymousURL.add("/fiola-svc-int/swagger-resources");
		
		//actuator
		allowedAnonymousURL.add("/fiola-svc-int/actuator");
		
		for (String url : allowedAnonymousURL) {
			if (uri.startsWith(url)) {
				retVal = true;
				break;
			}
		}

		return retVal;
	}

//	private boolean isAllowedForAllLoggedUserURL(HttpServletRequest request) {
//		boolean retVal = false;
//		String uri = request.getRequestURI();
//
//		List<String> allowedForAllLoggedUserURL = new ArrayList<String>();
//		allowedForAllLoggedUserURL.add("/fiola-svc-int/mdo");
//		allowedForAllLoggedUserURL.add("/fiola-svc-int/translog");
//		allowedForAllLoggedUserURL.add("/fiola-svc-int/customers");
//
//		for (String url : allowedForAllLoggedUserURL) {
//			if (uri.startsWith(url)) {
//				retVal = true;
//				gLog.info("Requested feature is accessible because this is allowed for all logged users.");
//				break;
//			}
//		}
//
//		return retVal;
//	}

	// Added by Alfian
//	private boolean isRequestedPageAllowed(HttpServletRequest request, UserDetailResponse userDetail) {
//		boolean retVal = false;
//		String uri = request.getRequestURI();
//		gLog.info("Requested feature : " + uri);
//
//		try {
//			UserFeatureResponse response = uidmService.getUserFeatures(userDetail.getUserDetail().getUserId());
//
//			for (UserFeature allowedPage : response.getListOfUserFeatures()) {
//				// ignore root access link
//				if (allowedPage.getAccessLink() == null)
//					continue;
//
//				if (allowedPage.getAccessLink().contains("~")) {
//					if (allowedPage.getAccessLink().split("~")[1] != null) {
//						/**
//						 * @notes Modified
//						 */
//						String accessLink = allowedPage.getAccessLink().split("~")[1];
//						if (accessLink.contains(",")) {
//							String[] split = accessLink.split(",");
//							for (int i = 0; i < split.length; i++) {
//								if (uri.startsWith(split[i])) {
//									retVal = true;
//									break;
//								}
//							}
//						} else if (uri.startsWith(accessLink)) {
//							retVal = true;
//							break;
//						}
//					}
//				}
//			}
//		} catch (Exception e) {
//			gLog.info("Error getting user features by loginSessionId, ", e);
//		}
//
//		if (!retVal)
//			gLog.info("Requested feature is not accessible");
//		else
//			gLog.info("Requested feature is accessible");
//
//		return retVal;
//	}
}
