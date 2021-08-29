package alf.security.fiola.utility.common;

import java.io.Serializable;

import alf.security.fiola.internals.model.LoggedUserDetail;

public class BaseRequest implements Serializable {

	private static final long serialVersionUID = -3891802575664601011L;
	private String loginSessionId;
	private LoggedUserDetail loggedUserDetail;

	public String getLoginSessionId() {
		return loginSessionId;
	}

	public void setLoginSessionId(String loginSessionId) {
		this.loginSessionId = loginSessionId;
	}

	public LoggedUserDetail getLoggedUserDetail() {
		return loggedUserDetail;
	}

	public void setLoggedUserDetail(LoggedUserDetail loggedUserDetail) {
		this.loggedUserDetail = loggedUserDetail;
	}

	@Override
	public String toString() {
		return "BaseRequest [loginSessionId=" + loginSessionId + ", loggedUserDetail=" + loggedUserDetail + "]";
	}
}
