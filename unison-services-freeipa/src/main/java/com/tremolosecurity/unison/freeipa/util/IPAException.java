package com.tremolosecurity.unison.freeipa.util;

import com.tremolosecurity.provisioning.core.ProvisioningException;

public class IPAException extends ProvisioningException {

	int code;
	String name;
	
	public IPAException(String msg) {
		super(msg);
		
	}
	
	public IPAException(String msg,Throwable t) {
		super(msg,t);
		
	}

	public int getCode() {
		return code;
	}

	public void setCode(int code) {
		this.code = code;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}
	
	

}
