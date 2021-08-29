package alf.security.fiola.config.aspect;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import alf.security.fiola.internals.service.BaseService;

@Aspect
@Component
public class LogAdvice {

	@Autowired
	HttpServletRequest request;
	
	@Autowired
	BaseService baseService;

	Logger gLog;

	@PostConstruct
	public void init() {
		gLog = baseService.getTransLog();
	}

	@Pointcut("@target(org.springframework.stereotype.Controller)")
	private void anyController() {
	}

	@Pointcut("@annotation(org.springframework.web.bind.annotation.RequestMapping)")
	private void anyRequestMapping() {
	}

	// the execution of any method defined in the bca package or a
	// sub-package
	@Pointcut("execution(* bca..*.*(..))")
	private void anyMethod() {
	}

	@Pointcut("execution(* bca..*.controller.*.save*(..))")
	private void saveMethod() {
	}

	@Pointcut("execution(* bca..*.controller.*.delete*(..))")
	private void deleteMethod() {
	}

	@Pointcut("execution(* bca..*.controller.*.update*(..))")
	private void updateMethod() {
	}

	@Before("(anyController() && anyRequestMapping()) && (saveMethod() || updateMethod())")
	public void logBeforeSaveOrUpdate(JoinPoint joinPoint) {
		gLog.info("*** BEFORE invoking SAVE joinPoint={}", niceName(joinPoint));
		for (Object arg : joinPoint.getArgs()) {
			// if (arg instanceof BaseForm) {
			gLog.debug("FORM BEAN={}", arg);
			gLog.debug("Principal={}", getPrincipal(request));
			// ((BaseForm) arg).setPrincipal(getPrincipal());
			// }
		}
		gLog.info("*** AFTER invoking SAVE joinPoint={}", niceName(joinPoint));
	}

	@Before("anyController() && anyRequestMapping() && deleteMethod()")
	public void logBeforeDelete(JoinPoint joinPoint) {
		gLog.info("*** Before invoking DELETE joinPoint={}", niceName(joinPoint));
		for (Object arg : joinPoint.getArgs()) {
			// if (arg instanceof BaseForm) {
			gLog.debug("FORM BEAN={}", arg);
			gLog.debug("Principal={}", getPrincipal(request));
			// ((BaseForm) arg).setPrincipal(getPrincipal());
			// }
		}
		gLog.info("*** AFTER invoking DELETE joinPoint={}", niceName(joinPoint));
	}

	@Around("anyController() && anyRequestMapping() && !saveMethod()")
	public Object logAround(ProceedingJoinPoint pjp) throws Throwable {
		gLog.info("BEFORE invoking method {}", niceName(pjp));
		Object result = pjp.proceed();

		gLog.info("AFTER invoking method {}", pjp.getTarget().getClass() + "::" + pjp.getSignature().getName());
		return result;
	}

	@AfterThrowing(pointcut = "anyController() && anyRequestMapping()", throwing = "error")
	public void logAfterThrowing(JoinPoint joinPoint, Throwable error) {
		gLog.info("AFTER THROWING invoking method {}", niceName(joinPoint));
		gLog.error("ERROR : " + error.getMessage(), error);
	}

	private String niceName(JoinPoint joinPoint) {
		return joinPoint.getTarget().getClass() + "::" + joinPoint.getSignature().getName();// +
																							// "\n\targs:"
		// + Arrays.toString(joinPoint.getArgs());
	}

	private String getPrincipal(HttpServletRequest request) {
		return request.getHeader("Authorization").toString();
	}

}
