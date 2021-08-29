package alf.security.fiola.utility.database;

import javax.annotation.PostConstruct;

import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;

import alf.security.fiola.internals.service.BaseService;

public class DatabaseUtil {

	@Autowired
	BaseService baseService;

	static Logger gLog, eLog;

	@PostConstruct
	public void init() {
		gLog = baseService.getTransLog();
	}
	
	//TODO
}
