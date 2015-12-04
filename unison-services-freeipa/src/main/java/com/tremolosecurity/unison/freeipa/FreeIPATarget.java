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
	
	public void createUser(User arg0, Set<String> arg1, Map<String, Object> arg2)
			throws ProvisioningException {
		// TODO Auto-generated method stub
		
	}

	public void deleteUser(User arg0, Map<String, Object> arg1)
			throws ProvisioningException {
		// TODO Auto-generated method stub
		
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
				
				for (String attributeName : attributes) {
					if (resp.getResult().getResult().get(attributeName) instanceof List) {
						Attribute a = user.getAttribs().get(attributeName);
						if (a == null) {
							a = new Attribute(attributeName);
							user.getAttribs().put(attributeName, a);
						}
						List l = (List) resp.getResult().getResult().get(attributeName);
						for (Object o : l) {
							a.getValues().add((String) o);
						}
					} else {
						Attribute a = user.getAttribs().get(attributeName);
						if (a == null) {
							a = new Attribute(attributeName);
							user.getAttribs().put(attributeName, a);
						}
						a.getValues().add((String) resp.getResult().getResult().get(attributeName));
					}
				}
				
				for (Object o : ((List) resp.getResult().getResult().get("memberof_group"))) {
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
			throw new ProvisioningException(ipaResponse.getError());
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

	public void setUserPassword(User arg0, Map<String, Object> arg1)
			throws ProvisioningException {
		// TODO Auto-generated method stub
		
	}

	public void syncUser(User arg0, boolean arg1, Set<String> arg2,
			Map<String, Object> arg3) throws ProvisioningException {
		// TODO Auto-generated method stub
		
	}

}
