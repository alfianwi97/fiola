package alf.security.fiola.internals.model;

import java.io.Serializable;

public class LoggedUserDetail implements Serializable {

	private static final long serialVersionUID = 8031184757876224310L;
	private String userId;
	private String userName;
	private String email;
	private String officeCode;
	private String officerCode;

	private String jobTitleCode;
	private String jobTitleName;

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getOfficeCode() {
		return officeCode;
	}

	public void setOfficeCode(String officeCode) {
		this.officeCode = officeCode;
	}

	public String getOfficerCode() {
		return officerCode;
	}

	public void setOfficerCode(String officerCode) {
		this.officerCode = officerCode;
	}

	public String getJobTitleCode() {
		return jobTitleCode;
	}

	public void setJobTitleCode(String jobTitleCode) {
		this.jobTitleCode = jobTitleCode;
	}

	public String getJobTitleName() {
		return jobTitleName;
	}

	public void setJobTitleName(String jobTitleName) {
		this.jobTitleName = jobTitleName;
	}

	@Override
	public String toString() {
		return "LoggedUserDetail [userId=" + userId + ", userName=" + userName + ", email=" + email + ", officeCode="
				+ officeCode + ", officerCode=" + officerCode + ", jobTitleCode=" + jobTitleCode + ", jobTitleName="
				+ jobTitleName + "]";
	}

}
