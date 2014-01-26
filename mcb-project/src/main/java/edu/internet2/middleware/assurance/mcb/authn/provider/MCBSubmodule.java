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
package edu.internet2.middleware.assurance.mcb.authn.provider;

import javax.security.auth.login.LoginException;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.BeanNameAware;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationException;

/**
 * Interface definition for an authentication submodule for the MCB.
 * 
 * @author Paul Hethmon
 *
 */
public interface MCBSubmodule extends BeanNameAware {
	
    // Attribute key value for previous login failed.
    public static final String LOGIN_FAILED = "loginFailed";


	/**
	 * Display the necessary login form.
	 * 
	 * @param servlet
	 * @param request
	 * @param response
	 * @return true if the login form display was handled.
	 * @throws AuthenticationException
	 * @throws LoginException
	 */
    boolean displayLogin(MCBLoginServlet servlet, HttpServletRequest request,
            HttpServletResponse response)
    	throws AuthenticationException, LoginException;

    /**
     * Process the login. Validate credentials and return a true/false success status.
     * 
     * @param servlet
     * @param request
     * @param response
     * @return true if the login was successful.
     * @throws AuthenticationException
     * @throws LoginException
     */
    boolean processLogin(MCBLoginServlet servlet, HttpServletRequest request,
            HttpServletResponse response)
    	throws AuthenticationException, LoginException;

    /**
     * Called during startup to allow any one-time initialization to occur.
     */
    void init();
    
    public String getBeanName();
}
