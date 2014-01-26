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

import java.io.IOException;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationException;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;

/**
 * An MCB submodule that can will use the RemoteUser value to define the principal.
 * 
 * @author Paul Hethmon
 *
 */
public class RemoteUserSubmodule implements MCBSubmodule {

	private final Logger log = LoggerFactory.getLogger(RemoteUserSubmodule.class);
	private String beanName = null;
	private String protectedServletURL = null;

	/**
	 * Send control to the external servlet that will do the authentication.
	 */
	public boolean displayLogin(MCBLoginServlet servlet,
			HttpServletRequest request, HttpServletResponse response) {
		// forward control to the servlet.
		try {
			String profileUrl = HttpServletHelper.getContextRelativeUrl(request, protectedServletURL).buildURL();

			log.debug("Redirecting to {}", profileUrl);
			response.sendRedirect(profileUrl);
			return true;
		} catch (IOException ex) {
			log.error("Unable to redirect to remote user authentication servlet.", ex);
		}

		return false;
	}

	/**
	 * Retrieve the REMOTE_USER value from the request that the external servlet has set and set it
	 * as our principal.
	 */
	public boolean processLogin(MCBLoginServlet servlet,
			HttpServletRequest request, HttpServletResponse response) {

		MCBUsernamePrincipal principal = (MCBUsernamePrincipal) request.getSession().getAttribute(LoginHandler.PRINCIPAL_KEY);
		try {
			String principalName = DatatypeHelper.safeTrimOrNullString(request.getRemoteUser());
			if (principalName != null) {
				log.debug("Remote user identified as {} returning control back to authentication engine", principalName);

				principal.setName(principalName);

				request.setAttribute(LoginHandler.PRINCIPAL_KEY, principal);

				return true;
			} else {
				log.debug("No remote user identified by protected servlet.");
			}
		} catch (Exception e) {
			principal.setFailedLogin(e.getMessage());
			return false;
		}

		return false;
	}

	public void init() {
		// noop
	}

	public void setBeanName(String name) {
		beanName = name;
	}

	public String getBeanName() {
		return beanName;
	}


	public RemoteUserSubmodule(String protectedServletURL) {
		this.protectedServletURL = protectedServletURL;
	}
}
