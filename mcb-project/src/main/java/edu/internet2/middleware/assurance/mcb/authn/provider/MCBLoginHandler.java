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
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.security.auth.Subject;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.util.URLBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.PassiveAuthenticationException;
import edu.internet2.middleware.shibboleth.idp.authn.Saml2LoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal;
import edu.internet2.middleware.shibboleth.idp.authn.provider.AbstractLoginHandler;
import edu.internet2.middleware.shibboleth.idp.session.Session;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;

/**
 * The MCB Shibboleth login handler.
 * 
 * @author Paul Hethmon
 *
 */
public class MCBLoginHandler extends AbstractLoginHandler {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(MCBLoginHandler.class);
//    private final String version = "MCB Login Handler -- Version 1.0.1 (2014-04-11)";
	public static final String VERSION =  MCBLoginServlet.class.getPackage().getImplementationVersion(); //"1.1.2 (2014-04-11)";

    /** The URL of the servlet used to perform authentication. */
    private String authenticationServletURL;
    
    private boolean previousSession = false;
    
    private MCBConfiguration mcbConfiguration = null;
    

    /**
     * Constructor.
     * 
     * @param servletURL URL to the authentication servlet
     * @throws Exception 
     */
    public MCBLoginHandler() throws Exception {
        super();
        
        setSupportsPassive(true);
        setSupportsForceAuthentication(true);
        this.authenticationServletURL = "/Authn/MCB";
        
        String endofline = System.getProperty("line.separator");
        log.info(endofline + "=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=" + endofline + endofline);
        
        log.info("MCBLoginHandler -- " + VERSION);
		
		log.debug("MCBConfiguration bean = [{}]", mcbConfiguration);
    }

    /** {@inheritDoc} */
    public void login(final HttpServletRequest httpRequest, final HttpServletResponse httpResponse) {

		log.debug("MCBConfiguration bean = [{}]", mcbConfiguration);

    	ServletContext application = null;
    	LoginContext loginContext = null;
    	EntityDescriptor entityDescriptor = null;
    	String entityID = "(unknown)";

   		application = httpRequest.getSession().getServletContext();
		loginContext = (LoginContext)HttpServletHelper.getLoginContext(HttpServletHelper.getStorageService(application),
				application, httpRequest);
		
		entityDescriptor = HttpServletHelper.getRelyingPartyMetadata(loginContext.getRelyingPartyId(),
				HttpServletHelper.getRelyingPartyConfigurationManager(application));
		entityID = entityDescriptor.getEntityID();
		log.debug("Relying party = [{}]", entityID);
		List<String> requestedContexts = loginContext.getRequestedAuthenticationMethods();
		// TODO figure out what action to take if we have requested values and a default configuration value
		// we must remove the "unspecified" context, it has no meaning as a requested context
		if (requestedContexts != null) {
			for (String ctx: requestedContexts) {
				if (ctx.equals(AuthnContext.UNSPECIFIED_AUTHN_CTX) == true) {
					log.warn("Relying party [{}] requested the unspecified authncontext value. Removing.", entityID);
					requestedContexts.remove(ctx);
				}
			}
		} else if (loginContext.getDefaultAuthenticationMethod() != null) {
			// use the default method defined in Shib configuration
			requestedContexts = new ArrayList<String>();
			requestedContexts.add(loginContext.getDefaultAuthenticationMethod());
			log.debug("SP did not send requested context value. Adding default of [{}]", loginContext.getDefaultAuthenticationMethod());
		}
		
    	// look for a previous session first
		// allowed context values they have and what they used previously
        Session idpSession = (Session) httpRequest.getAttribute(Session.HTTP_SESSION_BINDING_ATTRIBUTE);
        if ((idpSession != null) && (previousSession == true) && (idpSession.getPrincipalName() != null)) {
            log.debug("Using existing IdP session for {}", idpSession.getPrincipalName());

    		if (loginContext.isForceAuthRequired() == true) {
    			log.debug("Service provider requested forced authentication. Skipping previous session handling.");
    	        HttpSession userSession = httpRequest.getSession();
    	        userSession.setAttribute(MCBLoginServlet.FORCE_REAUTH, Boolean.TRUE);
		    	// from the session, we can get the Subject
		    	Subject subj = idpSession.getSubject();
		    	// now we get the list of principals for this subject/session
		    	Set<Principal> ps =  subj.getPrincipals();
		    	log.debug("principals size = {}", ps.size());
		    	MCBUsernamePrincipal principal = null;
		    	// the set for us should only be one principal, look for the first one
		    	for (Principal p : ps) {
		    		log.debug("principal type is [{}]", p.getClass().toString());
		    		if (p instanceof MCBUsernamePrincipal) {
		    			principal = (MCBUsernamePrincipal) p;
		    		}
		    	}
	            if (log.isTraceEnabled() == true) {
	            	log.trace(principal.getDebugInfo());
	            }
	            // TODO
		    	// if we get a forceAuthn, by design we will reset the session entirely to
		    	// no satisfying contexts, so we retain the principal but no information about them
		    	principal.getCurrentContexts().clear();
		    	//principal.getPotentialContexts().clear();
		    	principal.setFailedCount(0);
		    	// save the original principal name, we don't allow it to change (typically)
		    	userSession.setAttribute(MCBLoginServlet.ORIGINAL_PRINCIPAL_NAME, principal.getName());
        		userSession.setAttribute(LoginHandler.PRINCIPAL_KEY, principal); // store it with the request
    		} else {
		    	// from the session, we can get the Subject
		    	Subject subj = idpSession.getSubject();
		    	// now we get the list of principals for this subject/session
		    	Set<Principal> ps =  subj.getPrincipals();
		    	log.debug("principals size = {}", ps.size());
		    	MCBUsernamePrincipal principal = null;
		    	// the set for us should only be one principal, look for the first one
		    	for (Principal p : ps) {
		    		log.debug("principal type is [{}]", p.getClass().toString());
		    		if (p instanceof MCBUsernamePrincipal) {
		    			principal = (MCBUsernamePrincipal) p;
		    		}
		    	}
		    	// if we have our principal type available, then use it
		    	if (principal != null) {
		    		httpRequest.setAttribute(LoginHandler.PRINCIPAL_KEY, principal);
		    		log.debug("{}", principal.toString(true));
		    	
		    		// 3 cases possible
		    		// Case 1) No requested contexts. Send back the current context.
		    		// Case 2) 1 requested context. If matched to a used context, send that back.
		    		// Case 3) 2 or more requested contexts. Must match in an ordered list fashion.
		    		
		    		if (requestedContexts.size() == 0) {
		    			// SP did not request a context, very simple case met, send what we have
						log.debug("Very simple case met. SP did not request a context for principal [{}]", principal.getName());
						httpRequest.setAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY, principal.getCurrentContexts().get(0));
						httpRequest.setAttribute(LoginHandler.PRINCIPAL_KEY, principal);
						AuthenticationEngine.returnToAuthenticationEngine(httpRequest, httpResponse);
						return;
		    		}

		    		// Get the valid satisfied contexts based on the request
					ArrayList<String> validContexts = mcbConfiguration.getSatisfyingContexts(requestedContexts);
					boolean valid = mcbConfiguration.isValid(principal.getCurrentContexts(), validContexts);
					log.debug("Used context listed in requested contexts = [{}]", valid);

					// if we matched an already used context and only one is in the list, just 
					// match and send that one back to the SP
		    		if ((requestedContexts.size() == 1) && (valid == true)) {
		    			// SP only requested 1, see if we match it
						log.debug("Simple case met. The used context is in the requested list for principal [{}]", principal.getName());
						httpRequest.setAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY, requestedContexts.get(0));
						httpRequest.setAttribute(LoginHandler.PRINCIPAL_KEY, principal);
						AuthenticationEngine.returnToAuthenticationEngine(httpRequest, httpResponse);
						return;
		    		}
		    		
		    		// Finally the complex case, we may satisfy the request or we may need to do more
		    		ArrayList<String> matchedContexts = new ArrayList<String>();
		    		ArrayList<String> missingContexts = new ArrayList<String>();
		    		for (String context: requestedContexts) {
		    			// check the contexts in the order given
		    			ArrayList<String> clist = new ArrayList<String>();
		    			clist.add(context);
		    			valid = mcbConfiguration.isValid(principal.getCurrentContexts(), clist);
		    			if (valid == true) {
		    				// we found a match
		    				log.debug("Adding context [{}] to matched list.", context);
		    				matchedContexts.add(context);
		    				break; // once we find a match, we can stop
		    			} else {
		    				log.debug("Adding context [{}} to the missing list", context);
		    				missingContexts.add(context);
		    			}
		    		}
		    		// so now we have a missing and matched list
		    		// if missing is empty and matched has a match, we are done
		    		if ((missingContexts.size() == 0) && (matchedContexts.size() > 0)) {
		    			// use the highest context value matched
						log.debug("Multiple context case met. A used context [{}] is in the requested list for principal [{}]", matchedContexts.get(matchedContexts.size()-1), principal.getName());
						httpRequest.setAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY, matchedContexts.get(matchedContexts.size()-1));
						httpRequest.setAttribute(LoginHandler.PRINCIPAL_KEY, principal);
						AuthenticationEngine.returnToAuthenticationEngine(httpRequest, httpResponse);
						return;
		    		}
		    		
		    		// at this point we must ask for upgraded authentication for the user, either 
		    		// nothing matched or the preferred context was missing from the user's list

		    		// save the original principal name, we don't allow it to change (typically)
					httpRequest.getSession().setAttribute(MCBLoginServlet.ORIGINAL_PRINCIPAL_NAME, principal.getName());
					// set the upgrade auth key in the session
					httpRequest.getSession().setAttribute(MCBLoginServlet.UPGRADE_AUTH, Boolean.TRUE);
		    	}
		    	// else we have an principal object we don't know about, so fall through to have authentication happen
    		}
        }
        if ((idpSession != null) && (idpSession.getPrincipalName() == null)) {
        	log.warn("Found existing idp session [{}] with a null principal.", idpSession.getSessionID());
        }
        if (idpSession == null) {
        	log.trace("No session found. Previous Session Support setting = [{}]", previousSession);
        } else {
        	log.trace("Session found. Previous Session Support setting = [{}]", previousSession);
        }
    	
        // At this point, we either do not have an existing session or force authentication has been requested
        
        // check for an isPassive request
        if (loginContext.isPassiveAuthRequired() == true) {
        	log.info("Passive authentication requested without a valid SSO session. Returning SAML error to SP [{}]", loginContext.getRelyingPartyId());
        	PassiveAuthenticationException pae = new PassiveAuthenticationException("Passive authentication not supported without a previous session.");
        	httpRequest.setAttribute(LoginHandler.AUTHENTICATION_EXCEPTION_KEY, pae);
        	// send them back with a SAML error, we can't support passive without a prior session
            AuthenticationEngine.returnToAuthenticationEngine(httpRequest, httpResponse);
            return;
        }
        
        // forward control to the servlet.
        try {
            StringBuilder pathBuilder = new StringBuilder();
            pathBuilder.append(httpRequest.getContextPath());
            if (!authenticationServletURL.startsWith("/")) {
                pathBuilder.append("/");
            }
            pathBuilder.append(authenticationServletURL);

            URLBuilder urlBuilder = new URLBuilder();
            urlBuilder.setScheme(httpRequest.getScheme());
            urlBuilder.setHost(httpRequest.getServerName());
            urlBuilder.setPort(httpRequest.getServerPort());
            urlBuilder.setPath(pathBuilder.toString());

            log.debug("Redirecting to {}", urlBuilder.buildURL());
            httpResponse.sendRedirect(urlBuilder.buildURL());
            return;
        } catch (IOException ex) {
            log.error("Unable to redirect to authentication servlet.", ex);
        }

    }

	public void setPreviousSession(boolean previousSession) {
		this.previousSession = previousSession;
	}

	public boolean previousSession() {
		return previousSession;
	}

	public MCBConfiguration getMcbConfiguration() {
		return mcbConfiguration;
	}

	public void setMcbConfiguration(MCBConfiguration mcbConfiguration) {
		this.mcbConfiguration = mcbConfiguration;
	}

}
