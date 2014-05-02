/*******************************************************************************
* Copyright 2013 Internet2 
* 
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at 
* 
*   http://www.apache.org/licenses/LICENSE-2.0
* 
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License. 
******************************************************************************/
/*
 * Licensed to the University Corporation for Advanced Internet Development, 
 * Inc. (UCAID) under one or more contributor license agreements.  See the 
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache 
 * License, Version 2.0 (the "License"); you may not use this file except in 
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package edu.internet2.middleware.assurance.mcb.authn.provider;

import java.security.Principal;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.velocity.VelocityContext;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationException;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal;
import edu.internet2.middleware.shibboleth.idp.authn.provider.UsernamePasswordCredential;

/**
 * An MCB authentication submodule implementing the JAAS interface.
 * 
 * @author Paul Hethmon
 *
 */
public class JAASLoginSubmodule implements MCBSubmodule {

	private final Logger log = LoggerFactory.getLogger(JAASLoginSubmodule.class);
	private String beanName = null;

	/** Name of JAAS configuration used to authenticate users. */
    private String jaasConfigName = "MCBUserPassAuth";
    private String jaasConfigFile = "login.config";
    private boolean useJsp = false;

    /** Login page name. */
    private String loginPage = "jaaslogin.vm";

    /** HTTP request parameter containing the user name. */
    private final String usernameAttribute = "j_username";

    /** HTTP request parameter containing the user's password. */
    private final String passwordAttribute = "j_password";

    /**
     * Display the login page for the user.
     */
	public boolean displayLogin(MCBLoginServlet servlet, HttpServletRequest request,
			HttpServletResponse response) throws AuthenticationException,
			LoginException {

		// if the user failed login, we stored the reason in the principal object
		// so pull it out if it exists
		MCBUsernamePrincipal principal = (MCBUsernamePrincipal) request.getSession().getAttribute(LoginHandler.PRINCIPAL_KEY);
		

		if (useJsp == false) {
			// Using Velocity template
			VelocityContext vCtx = new VelocityContext();
			if ((principal != null) && (principal.getFailedLogin() != null)) {
				vCtx.put("loginFailed", principal.getFailedLogin());
				log.debug("Failed count = [{}]", principal.getFailedCount());
			} else {
				vCtx.put("loginFailed", "");
			}
			Boolean upgradeAuth = (Boolean) request.getSession().getAttribute(MCBLoginServlet.UPGRADE_AUTH);
			request.getSession().removeAttribute(MCBLoginServlet.UPGRADE_AUTH);
			if ((upgradeAuth != null) && (upgradeAuth.booleanValue() == true)) {
				vCtx.put(MCBLoginServlet.UPGRADE_AUTH,"true");
			} else {
				vCtx.put(MCBLoginServlet.UPGRADE_AUTH,"");
			}
			// note that this is an force re-authentication request
			Boolean forceAuth = (Boolean) request.getSession().getAttribute(MCBLoginServlet.FORCE_REAUTH);
			request.getSession().removeAttribute(MCBLoginServlet.FORCE_REAUTH);
			if ((forceAuth != null) && (forceAuth.booleanValue() == true)) {
				vCtx.put(MCBLoginServlet.FORCE_REAUTH,"true");
			} else {
				vCtx.put(MCBLoginServlet.FORCE_REAUTH,"");
			}
			
			log.debug("Displaying Velocity password login template [{}]", loginPage);
			servlet.doVelocity(request, response, loginPage, vCtx);
		} else {
			// Using JSP login page
			if ((principal != null) && (principal.getFailedLogin() != null)) {
				request.setAttribute(JAASLoginSubmodule.LOGIN_FAILED, "true");
				log.debug("Failed count = [{}]", principal.getFailedCount());
			} else {
				request.removeAttribute(JAASLoginSubmodule.LOGIN_FAILED);
			}
			Boolean upgradeAuth = (Boolean) request.getSession().getAttribute(MCBLoginServlet.UPGRADE_AUTH);
			if ((upgradeAuth != null) && (upgradeAuth.booleanValue() == true)) {
				request.setAttribute(MCBLoginServlet.UPGRADE_AUTH, "true");
			} else {
				request.removeAttribute(MCBLoginServlet.UPGRADE_AUTH);
			}
			// note that this is an force re-authentication request
			Boolean forceAuth = (Boolean) request.getSession().getAttribute(MCBLoginServlet.FORCE_REAUTH);
			request.getSession().removeAttribute(MCBLoginServlet.FORCE_REAUTH);
			if ((forceAuth != null) && (forceAuth.booleanValue() == true)) {
				request.setAttribute(MCBLoginServlet.FORCE_REAUTH,"true");
			} else {
				request.setAttribute(MCBLoginServlet.FORCE_REAUTH,"");
			}
			
			log.debug("Displaying JSP login page [{}]", loginPage);
			servlet.redirectToLoginPage(request, response, null, loginPage);
		}

		principal.setFailedLogin(null);
		
		return true;
	}

	/**
	 * Process the login information submitted by the user.
	 * 
	 * @return true if login was successful
	 */
	public boolean processLogin(MCBLoginServlet servlet, HttpServletRequest request,
			HttpServletResponse response) throws AuthenticationException,
			LoginException {
		
    	MCBUsernamePrincipal principal = (MCBUsernamePrincipal) request.getSession().getAttribute(LoginHandler.PRINCIPAL_KEY);
    	
    	String loginid = DatatypeHelper.safeTrimOrNullString(request.getParameter(usernameAttribute));
    	String password = DatatypeHelper.safeTrimOrNullString(request.getParameter(passwordAttribute));
    	
    	try {
	    	Subject subject = authenticateUser(request, loginid, password);
	    	
	    	principal.setName(loginid);
	    	subject.getPrincipals().clear();
	    	subject.getPrincipals().add(principal);

	    	request.setAttribute(LoginHandler.SUBJECT_KEY, subject);
	    	request.setAttribute(LoginHandler.PRINCIPAL_KEY, principal);

	    	return true;
    	} catch (Exception e) {
    		principal.setFailedLogin(e.getMessage());
    		return false;
    	}
    	
	}

	/**
	 * Constructor
	 * @param jaasConfigFile The name of the JAAS configuration file.
	 * @param jaasConfigName The configuration element in the JAAS file to use.
	 * @param loginPage The login page to display. Default is assumed to be a Velocity template.
	 */
	public JAASLoginSubmodule(String jaasConfigFile, String jaasConfigName, String loginPage) {
		this(jaasConfigFile, jaasConfigName, loginPage, false);
	}

	/**
	 * Constructor that specifies needed configuration data
	 * @param jaasConfigFile The name of the JAAS configuration file.
	 * @param jaasConfigName The configuration element in the JAAS file to use.
	 * @param loginPage The login page to display. Default is assumed to be a Velocity template.
	 * @param useJsp If set to true, the login page is JSP and processed as such.
	 */
	public JAASLoginSubmodule(String jaasConfigFile, String jaasConfigName, String loginPage, boolean useJsp) {
		this.jaasConfigFile = jaasConfigFile;
		this.jaasConfigName = jaasConfigName;
		this.loginPage = loginPage;
		this.useJsp = useJsp;
		
		log.debug("Processing login page as JSP is [{}]", this.useJsp);
		log.debug("Setting JAAS configuration file to [{}]", this.jaasConfigFile);
		System.setProperty("java.security.auth.login.config", this.jaasConfigFile);
	}
	
	public void init() {
		log.info("JASSLoginSubmodule initialized.");
	}

	public void setBeanName(String name) {
		beanName = name;
	}

	public String getBeanName() {
		return beanName;
	}

    /**
     * Authenticate a username and password against JAAS. If authentication succeeds the name of the first principal, or
     * the username if that is empty, and the subject are placed into the request in their respective attributes.
     * 
     * @param request current authentication request
     * @param username the principal name of the user to be authenticated
     * @param password the password of the user to be authenticated
     * 
     * @throws LoginException thrown if there is a problem authenticating the user
     */
    protected Subject authenticateUser(HttpServletRequest request, String username, String password) throws LoginException {
        try {
            log.debug("Attempting to authenticate user {}", username);

            SimpleCallbackHandler cbh = new SimpleCallbackHandler(username, password);

            javax.security.auth.login.LoginContext jaasLoginCtx = new javax.security.auth.login.LoginContext(
                    jaasConfigName, cbh);

            jaasLoginCtx.login();
            log.debug("Successfully authenticated user {}", username);

            Subject loginSubject = jaasLoginCtx.getSubject();

            Set<Principal> principals = loginSubject.getPrincipals();
            principals.add(new UsernamePrincipal(username));

            Set<Object> publicCredentials = loginSubject.getPublicCredentials();

            Set<Object> privateCredentials = loginSubject.getPrivateCredentials();
            privateCredentials.add(new UsernamePasswordCredential(username, password));

            Subject userSubject = new Subject(false, principals, publicCredentials, privateCredentials);
            
            return userSubject;
        } catch (LoginException e) {
            log.debug("User authentication for " + username + " failed", e);
            throw e;
        } catch (Throwable e) {
            log.debug("User authentication for " + username + " failed", e);
            throw new LoginException("unknown authentication error");
        }
    }

    /**
     * A callback handler that provides static name and password data to a JAAS loging process.
     * 
     * This handler only supports {@link NameCallback} and {@link PasswordCallback}.
     */
    protected class SimpleCallbackHandler implements CallbackHandler {

        /** Name of the user. */
        private String uname;

        /** User's password. */
        private String pass;

        /**
         * Constructor.
         * 
         * @param username The username
         * @param password The password
         */
        public SimpleCallbackHandler(String username, String password) {
            uname = username;
            pass = password;
        }

        /**
         * Handle a callback.
         * 
         * @param callbacks The list of callbacks to process.
         * 
         * @throws UnsupportedCallbackException If callbacks has a callback other than {@link NameCallback} or
         *             {@link PasswordCallback}.
         */
        public void handle(final Callback[] callbacks) throws UnsupportedCallbackException {

            if (callbacks == null || callbacks.length == 0) {
                return;
            }

            for (Callback cb : callbacks) {
                if (cb instanceof NameCallback) {
                    NameCallback ncb = (NameCallback) cb;
                    ncb.setName(uname);
                } else if (cb instanceof PasswordCallback) {
                    PasswordCallback pcb = (PasswordCallback) cb;
                    if (pass != null) {
                    	pcb.setPassword(pass.toCharArray());
                    } else {
                    	pcb.setPassword(null);
                    }
                }
            }
        }
    }

}
