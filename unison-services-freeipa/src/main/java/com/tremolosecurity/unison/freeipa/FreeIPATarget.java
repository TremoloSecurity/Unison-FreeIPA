/*******************************************************************************
 * Copyright 2015 Tremolo Security, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.tremolosecurity.unison.freeipa;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.message.BasicNameValuePair;
import org.apache.log4j.Logger;

import com.google.gson.Gson;
import com.tremolosecurity.config.util.ConfigManager;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.provisioning.core.User;
import com.tremolosecurity.provisioning.core.UserStoreProvider;
import com.tremolosecurity.provisioning.core.Workflow;
import com.tremolosecurity.provisioning.core.ProvisioningUtil.ActionType;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.unison.freeipa.json.IPACall;
import com.tremolosecurity.unison.freeipa.json.IPAResponse;
import com.tremolosecurity.unison.freeipa.util.HttpCon;




public class FreeIPATarget implements UserStoreProvider{

	static Logger logger = Logger.getLogger(FreeIPATarget.class.getName());
	
	String url;
	String userName;
	String password;
	private ConfigManager cfgMgr;

	private String name;
	
	
	private void addGroup(String userID, String groupName,
			HttpCon con, int approvalID, Workflow workflow) throws Exception {
		
		
		IPACall addGroup = new IPACall();
		addGroup.setId(0);
		addGroup.setMethod("group_add_member");
		
		ArrayList<Object> groupAddList = new ArrayList<Object>();
		groupAddList.add(new ArrayList<Object>());
		((ArrayList<Object>)groupAddList.get(0)).add(groupName);
		groupAddList.add(new HashMap<String,String>());
		((HashMap<String,String>) groupAddList.get(1)).put("user", userID);
		
		addGroup.getParams().add(groupAddList);
		
		IPAResponse resp = this.executeIPACall(addGroup, con);
		
		this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Add,  approvalID, workflow, "group", groupName);
		
	}
	
	private void removeGroup(String userID, String groupName,
			HttpCon con, int approvalID, Workflow workflow) throws Exception {
		
		IPACall removeGroup = new IPACall();
		removeGroup.setId(0);
		removeGroup.setMethod("group_remove_member");
		
		ArrayList<Object> groupAddList = new ArrayList<Object>();
		groupAddList.add(new ArrayList<Object>());
		((ArrayList<Object>)groupAddList.get(0)).add(groupName);
		groupAddList.add(new HashMap<String,String>());
		((HashMap<String,String>) groupAddList.get(1)).put("user", userID);
		
		removeGroup.getParams().add(groupAddList);
		
		IPAResponse resp = this.executeIPACall(removeGroup, con);
		
		this.cfgMgr.getProvisioningEngine().logAction(name,false, ActionType.Delete,  approvalID, workflow, "group", groupName);
		
	}
	
	
	public void createUser(User user, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		try {
			HttpCon con = this.createClient();
			
			try {
				IPACall createUser = new IPACall();
				createUser.setId(0);
				createUser.setMethod("user_add");
				
				ArrayList<String> userArray = new ArrayList<String>();
				userArray.add(user.getUserID());
				createUser.getParams().add(userArray);
				
				HashMap<String,Object> userAttrs = new HashMap<String,Object>();
				
				for (String attrName : attributes) {
					Attribute attr = user.getAttribs().get(attrName);
					
					if (attr != null && ! attr.getName().equalsIgnoreCase("uid")) {
						if (attr.getValues().size() == 1) {
							userAttrs.put(attr.getName(), attr.getValues().get(0));
						} else {
							ArrayList vals = new ArrayList<String>();
							vals.addAll(attr.getValues());
							userAttrs.put(attr.getName(), vals);
						}
						
						
					}
				}
				
				createUser.getParams().add(userAttrs);
				
				IPAResponse resp = this.executeIPACall(createUser, con);
				
				this.cfgMgr.getProvisioningEngine().logAction(name,true, ActionType.Add,  approvalID, workflow, "uid", user.getUserID());
				
			} finally {
				if (con != null) {
					con.getBcm().shutdown();
				}
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not run search",e);
		}
		
	}

	public void deleteUser(User user, Map<String, Object> request)
			throws ProvisioningException {
		
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		try {
			HttpCon con = this.createClient();
			
			try {
				IPACall deleteUser = new IPACall();
				deleteUser.setId(0);
				deleteUser.setMethod("user_del");
				
				ArrayList<String> userArray = new ArrayList<String>();
				userArray.add(user.getUserID());
				deleteUser.getParams().add(userArray);
				
				HashMap<String,String> additionalParams = new HashMap<String,String>();
				
				deleteUser.getParams().add(additionalParams);
				
				IPAResponse resp = this.executeIPACall(deleteUser, con);
				
				this.cfgMgr.getProvisioningEngine().logAction(name,true, ActionType.Delete,  approvalID, workflow, "uid", user.getUserID());
			} finally {
				if (con != null) {
					con.getBcm().shutdown();
				}
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not run search",e);
		}
		
	}

	public User findUser(String userID, Set<String> attributes, Map<String, Object> request)
			throws ProvisioningException {
		try {
			HttpCon con = this.createClient();
			
			try {
				IPACall userSearch = new IPACall();
				userSearch.setId(0);
				userSearch.setMethod("user_show");
				
				ArrayList<String> userArray = new ArrayList<String>();
				userArray.add(userID);
				userSearch.getParams().add(userArray);
				
				HashMap<String,String> additionalParams = new HashMap<String,String>();
				additionalParams.put("all", "true");
				additionalParams.put("rights", "true");
				userSearch.getParams().add(additionalParams);
				
				IPAResponse resp = this.executeIPACall(userSearch, con);
				
				User user = new User();
				user.setUserID(userID);
				Map<String,Object> results = (Map<String,Object>) resp.getResult().getResult();
				
				for (String attributeName : attributes) {
					
					if (results.get(attributeName) instanceof List) {
						Attribute a = user.getAttribs().get(attributeName);
						if (a == null) {
							a = new Attribute(attributeName);
							user.getAttribs().put(attributeName, a);
						}
						List l = (List) results.get(attributeName);
						for (Object o : l) {
							a.getValues().add((String) o);
						}
					} else {
						Attribute a = user.getAttribs().get(attributeName);
						if (a == null) {
							a = new Attribute(attributeName);
							user.getAttribs().put(attributeName, a);
						}
						a.getValues().add((String) results.get(attributeName));
					}
				}
				
				for (Object o : ((List) results.get("memberof_group"))) {
					String groupName = (String) o;
					user.getGroups().add(groupName);
				}
				
				return user;
				
			} finally {
				if (con != null) {
					con.getBcm().shutdown();
				}
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not run search",e);
		}
		
	}
	
	private IPAResponse executeIPACall(IPACall ipaCall,HttpCon con) throws ProvisioningException, ClientProtocolException, IOException {
		
		Gson gson = new Gson();
		String json = gson.toJson(ipaCall);
		
		if (logger.isDebugEnabled()) {
			logger.debug("Outbound JSON : '" + json + "'");
		}
		
		HttpClient http = con.getHttp();
		
		StringEntity str = new StringEntity(json,ContentType.APPLICATION_JSON);
		HttpPost httppost = new HttpPost(this.url + "/ipa/session/json");
		httppost.addHeader("Referer", this.url + "/ipa/ui/");
		httppost.setEntity(str);
		HttpResponse resp = http.execute(httppost);
		
		
		
		
		
		
		BufferedReader in = new BufferedReader(new InputStreamReader(resp.getEntity().getContent()));
		StringBuffer b = new StringBuffer();
		String line = null;
		while ((line = in.readLine()) != null) {
			b.append(line);
		}
		
		if (logger.isDebugEnabled()) {
			logger.info("Inbound JSON : " + b.toString());
		}
		
		IPAResponse ipaResponse = gson.fromJson(b.toString(), IPAResponse.class);
		
		if (ipaResponse.getError() != null) {
			throw new ProvisioningException(ipaResponse.getError().getMessage());
		} else {
			return ipaResponse;
		}
		
	}

	public void init(Map<String, Attribute> cfg, ConfigManager cfgMgr,
			String name) throws ProvisioningException {
		this.url = this.loadOption("url", cfg, false);
		this.userName = this.loadOption("userName", cfg, false);
		this.password = this.loadOption("password", cfg, true);
		this.cfgMgr = cfgMgr;
		this.name = name;
		
	}
	
	private String loadOption(String name,Map<String,Attribute> cfg,boolean mask) throws ProvisioningException{
		if (! cfg.containsKey(name)) {
			throw new ProvisioningException(name + " is required");
		} else {
			String val = cfg.get(name).getValues().get(0); 
			if (! mask) {
				logger.info("Config " + name + "='" + val + "'");
			} else {
				logger.info("Config " + name + "='*****'");
			}
			
			return val;
		}
	}
	
	private HttpCon createClient() throws Exception {
		return this.createClient(this.userName, this.password);
	}
	
	private HttpCon createClient(String lusername,String lpassword) throws Exception {
		
		BasicHttpClientConnectionManager bhcm = new BasicHttpClientConnectionManager(cfgMgr.getHttpClientSocketRegistry());
		
		
		RequestConfig rc = RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).build();
		
		    CloseableHttpClient http = HttpClients.custom().setConnectionManager(bhcm).setDefaultRequestConfig(rc).build();
		    
		    http.execute(new HttpGet(this.url + "/ipa/session/login_kerberos")).close();
		    
		    
		doLogin(lusername, lpassword, http);
		
		HttpCon con = new HttpCon();
		con.setBcm(bhcm);
		con.setHttp(http);
		
		return con;
		
	}

	private void doLogin(String lusername, String lpassword,
			CloseableHttpClient http) throws UnsupportedEncodingException,
			IOException, ClientProtocolException {
		HttpPost httppost = new HttpPost(this.url + "/ipa/session/login_password");
		
		List<NameValuePair> formparams = new ArrayList<NameValuePair>();
		formparams.add(new BasicNameValuePair("user", lusername));
		formparams.add(new BasicNameValuePair("password", lpassword));
		UrlEncodedFormEntity entity = new UrlEncodedFormEntity(formparams, "UTF-8");

		
		httppost.setEntity(entity);
		
		CloseableHttpResponse response = http.execute(httppost);
		if (logger.isDebugEnabled()) {
			logger.debug("Login response : " + response.getStatusLine().getStatusCode());
		}
		
		response.close();
	}

	public void setUserPassword(User user, Map<String, Object> request)
			throws ProvisioningException {
		int approvalID = 0;
		if (request.containsKey("APPROVAL_ID")) {
			approvalID = (Integer) request.get("APPROVAL_ID");
		}
		
		Workflow workflow = (Workflow) request.get("WORKFLOW");
		
		try {
			HttpCon con = this.createClient();
			
			try {
				IPACall setPassword = new IPACall();
				setPassword.setId(0);
				setPassword.setMethod("passwd");
				
				ArrayList<String> userArray = new ArrayList<String>();
				userArray.add(user.getUserID());
				setPassword.getParams().add(userArray);
				
				HashMap<String,String> additionalParams = new HashMap<String,String>();
				additionalParams.put("password", user.getPassword());
				setPassword.getParams().add(additionalParams);
				
				IPAResponse resp = this.executeIPACall(setPassword, con);
				con.getBcm().shutdown();
				
				//no we need to reset the password, this is a hack.  right way is to tell IPA the user doesn't need to reset their password
				HttpPost httppost = new HttpPost(this.url + "/ipa/session/change_password");
				httppost.addHeader("Referer", this.url + "/ipa/ui/");	
				List<NameValuePair> formparams = new ArrayList<NameValuePair>();
				formparams.add(new BasicNameValuePair("user", user.getUserID()));
				formparams.add(new BasicNameValuePair("old_password", user.getPassword()));
				formparams.add(new BasicNameValuePair("new_password", user.getPassword()));
				UrlEncodedFormEntity entity = new UrlEncodedFormEntity(formparams, "UTF-8");

				
				httppost.setEntity(entity);
				
				
				
				con = this.createClient(user.getUserID(), user.getPassword());
				CloseableHttpClient http = con.getHttp();
				 
				
				CloseableHttpResponse httpResp = http.execute(httppost);
				
				if (logger.isDebugEnabled()) {
					logger.debug("Response of password reset : " + httpResp.getStatusLine().getStatusCode());
				}
				
				
				this.cfgMgr.getProvisioningEngine().logAction(name,true, ActionType.Delete,  approvalID, workflow, "uid", user.getUserID());
			} finally {
				if (con != null) {
					con.getBcm().shutdown();
				}
			}
		} catch (Exception e) {
			throw new ProvisioningException("Could not run search",e);
		}
		
	}

	public void syncUser(User arg0, boolean arg1, Set<String> arg2,
			Map<String, Object> arg3) throws ProvisioningException {
		// TODO Auto-generated method stub
		
	}

}
