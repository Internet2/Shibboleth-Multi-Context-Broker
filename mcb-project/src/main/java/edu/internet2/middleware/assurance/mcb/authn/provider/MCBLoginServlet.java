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
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.assurance.mcb.authn.provider.ui.IDPUIHandler;
import edu.internet2.middleware.assurance.mcb.config.Method;
import edu.internet2.middleware.assurance.mcb.exception.UserInitiatedLoginFailureException;
import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationException;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;

/**
 * Handle the actual authentication of the end user based on the MCB configuration.
 * 
 * @author Paul Hethmon
 *
 */
public class MCBLoginServlet extends HttpServlet {

	public static final String VERSION =  MCBLoginServlet.class.getPackage().getImplementationVersion(); //"1.1.2 (2014-04-11)";
	/**
	 * Serial UID 
	 */
	private static final long serialVersionUID = 63836487183733520L;

	/** Class logger. */
    private final Logger log = LoggerFactory.getLogger(MCBLoginServlet.class);
    
    private MCBConfiguration mcbConfig;
    
    /** Velocity engine to use to render login form. */
    private VelocityEngine velocity;

    // Parameter name used to pass the method list to the Velocity template
    public static final String METHOD_LIST_PARAM_NAME = "methodlist";
    // Parameter name used in the select method form to pass the selected value back to the MCB
    public static final String SELECTED_METHOD_PARAM_NAME = "selectedmethod";
    // Parameter name used to control whether we are entering the authentication step
    public static final String PERFORM_AUTHENTICATION_PARAM_NAME = "performauthentication";
    // Parameter name for the submodule in use
    public static final String SUBMODULE_PARAM_NAME = "submodule";
    // Parameter name for upgrading user auth when they have a session
    public static final String UPGRADE_AUTH = "upgradeAuth";
    // Parameter name for re-authenticating the user
    public static final String FORCE_REAUTH = "forceReAuth";
    // Parameter name for bypassing reauth if user selects satisfied method
    public static final String BYPASS_SATISFIED_METHODS = "bypassSatisfiedMethods";
    // Parameter name for the original principal name
    public static final String ORIGINAL_PRINCIPAL_NAME = "originalPrincipalName";
    
    /** {@inheritDoc} */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);

        log.info(VERSION);
        
        mcbConfig = (MCBConfiguration) getServletContext().getAttribute("mcb.Configuration");
        log.debug("mcbConfig = [{}]", mcbConfig);
        
        // Initial our velocity engine
        log.debug("Initializing velocity engine using [{}]", mcbConfig.getVelocityPropertiesFile());
        velocity = new VelocityEngine();
        velocity.init(mcbConfig.getVelocityPropertiesFile());
    }

    /** {@inheritDoc} */
    protected void service(HttpServletRequest request, HttpServletResponse response) throws ServletException,
            IOException {
    	ServletContext application = null;
    	LoginContext loginContext = null;
    	EntityDescriptor entityDescriptor = null;
    	String entityID = null;
    	String selectedMethodName = null;
    	MCBUsernamePrincipal principal = null;
        HttpSession userSession = request.getSession();

        log.trace("=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+");
    	log.debug("Request received from [{}]", request.getRemoteAddr());
    	// either find or create the principal object we will use for this user
    	principal = (MCBUsernamePrincipal) userSession.getAttribute(LoginHandler.PRINCIPAL_KEY);
    	if (principal == null) {
    		log.debug("Creating new principal object for request.");
    		principal = new MCBUsernamePrincipal("[principal]");
    		userSession.setAttribute(LoginHandler.PRINCIPAL_KEY, principal); // store it with the request
    	}
    	log.debug("principal = [{}]", principal);
    	
    	try {
			application = this.getServletContext();
			loginContext = (LoginContext)HttpServletHelper.getLoginContext(HttpServletHelper.getStorageService(application),
					application, request);
			entityDescriptor = HttpServletHelper.getRelyingPartyMetadata(loginContext.getRelyingPartyId(),
					HttpServletHelper.getRelyingPartyConfigurationManager(application));
			entityID = entityDescriptor.getEntityID();
			log.debug("Relying party = [{}]", entityID);
    	} catch (Exception e) {
    		log.error("Unable to determine Relying Party. Probable bookmark access to servlet.");
			request.setAttribute(LoginHandler.AUTHENTICATION_ERROR_KEY, StatusCode.REQUEST_UNSUPPORTED_URI);
			AuthenticationEngine.returnToAuthenticationEngine(request, response);
    		return;
    	}
    	
		// Check and see if there is an existing session we are upgrading
		Boolean doUpgrade =  (Boolean) userSession.getAttribute(UPGRADE_AUTH);
		if ((doUpgrade != null) && (doUpgrade.booleanValue() == true)) {
			log.debug("Performing authentication upgrade for request.");
			List<String> requestedContexts = getRequestedContexts(request);
			//userSession.removeAttribute(UPGRADE_AUTH); // remove the key
			showMethods(request, response, principal.getPotentialContexts(), requestedContexts);
			return;
		}
		
		// Check and see if there is an existing session we are forcing to re-authenticate
		Boolean forceAuth =  (Boolean) userSession.getAttribute(FORCE_REAUTH);
		if ((forceAuth != null) && (forceAuth.booleanValue() == true)) {
			log.debug("Performing force re-authentication for request.");
			List<String> requestedContexts = getRequestedContexts(request);
			//userSession.removeAttribute(FORCE_REAUTH); // remove the key
			showMethods(request, response, principal.getPotentialContexts(), requestedContexts);
			return;
		}
		

		// If this is the submission of the login form, we simply need to look up the stored submodule performing the
		// authentication and let that submodule validate the user. No need to figure out which one again.
		Boolean doAuth =  (Boolean) userSession.getAttribute(PERFORM_AUTHENTICATION_PARAM_NAME);
		if ((doAuth != null) && (doAuth.booleanValue() == true)) {
			log.debug("Performing authentication for request.");
			boolean authenticated = performAuthentication(request, response, entityID);
			log.debug("Authentication result = [{}]", authenticated);
			return;
		}
		
		// We next need to figure out if we are here as the second leg of selecting the authentication
		// method. If we are, we must validate that the selected method is allowed to prevent a maliscious user
		// from changing the submitted value from the permitted values.
		selectedMethodName = DatatypeHelper.safeTrimOrNullString(request.getParameter(SELECTED_METHOD_PARAM_NAME));
		log.debug("Selected method name = [{}]", selectedMethodName);
		
		// only try to validate the method name if we have one
		if (selectedMethodName != null) {
			log.debug("User selected authentication method to use of [{}]", selectedMethodName);
			boolean selected = processSelectedMethod(request, response, selectedMethodName);
			if (selected == true) {
				return;
			}
		}
		
		// So at this point, either this is the first leg or the user has tried to submit a non-permitted method name
    	// check and see what our default behavior is
		log.debug("Either first leg or bad method selected. Going to show methods.");
		showMethods(request, response);
    	
        return;
    }

    /**
     * Perform the authentication step.
     * @param request
     * @param response
     * @param entityID
     * @return
     */
    protected boolean performAuthentication(HttpServletRequest request, HttpServletResponse response, String entityID) {
		log.debug("Found 2nd leg of authentication, performing authentication.");
    	MCBUsernamePrincipal principal = null;
        HttpSession userSession = request.getSession();
		List<String> requestedContexts = getRequestedContexts(request);
		String methodUsed;
//		String contextUsed;
		MCBSubmodule sub;

		try {
			sub = (MCBSubmodule) userSession.getAttribute(SUBMODULE_PARAM_NAME);
			// mark us not in authentication
			userSession.setAttribute(PERFORM_AUTHENTICATION_PARAM_NAME, Boolean.FALSE);
			methodUsed = (String) userSession.getAttribute(SELECTED_METHOD_PARAM_NAME);
			//contextUsed = (String) userSession.getAttribute(CONTEXT_PARAM_NAME);
			
			boolean b = sub.processLogin(this, request, response);
			log.debug("submodule process login returned [{}]", b);
			principal = (MCBUsernamePrincipal) userSession.getAttribute(LoginHandler.PRINCIPAL_KEY);
			if (b == true) {
				// check for the principal switching
				String originalPrincipalName = (String) userSession.getAttribute(ORIGINAL_PRINCIPAL_NAME);
				// if we have an original principal name and if we are not configured to allow switching
				if ((originalPrincipalName != null) && (mcbConfig.getAllowPrincipalSwitching() != MCBConfiguration.AllowPrincipalSwitching.ANY)) {
					// do the check
					boolean switched = false;
					if ((mcbConfig.getAllowPrincipalSwitching() != MCBConfiguration.AllowPrincipalSwitching.CASE_ONLY) && 
							(principal.getName().equalsIgnoreCase(originalPrincipalName) == false)) {
						// principal's changed by more than case, fail
						switched = true;
					} else if (principal.getName().equals(originalPrincipalName) == false) {
						// principal's name changed in some way, fail
						switched = true;
					}
					if (switched == true) {
						log.warn("Failing authentication attempt due to principal name changing. Original = [{}]. New = [{}]", originalPrincipalName, principal.getName());
		    			AuthenticationException ae = new AuthenticationException("New principal name does not match prior session principal name.");
		            	request.setAttribute(LoginHandler.AUTHENTICATION_EXCEPTION_KEY, ae);
		            	request.removeAttribute(LoginHandler.PRINCIPAL_KEY); // remove the principal
		            	request.removeAttribute(ORIGINAL_PRINCIPAL_NAME);    // remove the original name
		            	// we effectively kill any session with this browser
		            	// send them back with a SAML error
		                AuthenticationEngine.returnToAuthenticationEngine(request, response);
		                return true;
					}
				}
				
				
				// perform attribute resolution now
				MCBAttributeResolver ar = new MCBAttributeResolver();
				log.debug("Running attribute resolution for principal [{}]", principal.getName());
				ar.resolve(this, request, response, principal.getName(), entityID);
				
				// Get the list of contexts this user is potentially allowed to use.
				BaseAttribute ba = ar.getAttributes().get(mcbConfig.getAttributeResolverID());
				log.debug("Found idms attribute: {}", ba);
				ArrayList<String> potentialContexts = ar.getValueList(ba);
				log.debug("Found [{}] values in attribute.", potentialContexts.size());
				// Save what this user is allowed to use
				principal.setPotentialContexts(potentialContexts);
				
				// Check and see if the context used is allowed
				// we have an authenticated user based on the configuration context
				// we may have a list of requested contexts from the SP
				// we must validate that everything matches up in order to let this user go on
				log.debug("User authenticated with method [{}]", methodUsed);
				// Now get the list of context values this method is valid for
				ArrayList<String> usedContextList = mcbConfig.getContextFromMethod(methodUsed);
				// save this list with the principal, we assume there are some already
				principal.getCurrentContexts().addAll(usedContextList);
				if (log.isTraceEnabled() == true) {
					for (String ctx: usedContextList) {
						log.trace("Used context = [{}]", ctx);
					}
				}
				
				// At this point we've authenticated the user with the given method. That
				// method gives us a list of valid contexts it can be used to satisfy. We
				// also have the list of contexts this user is authorized for. Finally, we
				// have the list of requested context values from the SP.
				
				// check 1 -- if user has no contexts from idms and SP did not request one
				// see if the configuration allows this to work
				if ((potentialContexts.size() == 0) && (requestedContexts.size() == 0) && (mcbConfig.isPrincipalAuthnContextRequired() == false)) {
					log.debug("User has no allowed contexts. SP did not request context. principalAuthnContextRequired is false. Authenticating user as successful.");
					// set the authentication context that was used
					principal.setCurrentContexts(usedContextList); // save the context values used
					request.setAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY, usedContextList.get(0));
					request.setAttribute(LoginHandler.PRINCIPAL_KEY, principal);
					request.setAttribute(LoginHandler.AUTHENTICATION_INSTANT_KEY, new DateTime());
					AuthenticationEngine.returnToAuthenticationEngine(request, response);
					return true;
				}
				
				// check 2 -- can the user use the context they just used?
				boolean valid = mcbConfig.isValid(usedContextList, potentialContexts);
				log.debug("Used context listed in valid contexts = [{}]", valid);
				if (valid == false) {
					// the user must select another method to authenticate with
					// at this point, only show the allowed methods to the user
					log.debug("User [{}] used a context NOT on the potential context list. They must re-authenticate with a valid context.", principal.getName());
					userSession.setAttribute(UPGRADE_AUTH, Boolean.TRUE);
					showMethods(request, response, potentialContexts, requestedContexts);
					return false;
				}
				log.debug("Used context for principal [{}] is on the potential allowed list.", principal.getName());
				
				// check 3 -- does the used context list match the requested context list?
				log.debug("requestedContexts = [{}]", requestedContexts.size());
				for (String rc: requestedContexts) {
					log.debug("   rc = [{}]", rc);
				}
				ArrayList<String> validContexts = mcbConfig.getSatisfyingContexts(requestedContexts);
				log.debug("validContexts = [{}]", validContexts.size());
				for (String vc: validContexts) {
					log.debug("   vc = [{}]", vc);
				}
				valid = mcbConfig.isValid(usedContextList, validContexts);
				log.debug("Used context listed in requested contexts = [{}]", valid);
				
				// ----------------------------
				
	    		// Finally the complex case, we may satisfy the request or we may need to do more
	    		ArrayList<String> matchedContexts = new ArrayList<String>();
	    		ArrayList<String> missingContexts = new ArrayList<String>();
	    		for (String context: requestedContexts) {
	    			// check the contexts in the order given
	    			ArrayList<String> clist = new ArrayList<String>();
	    			clist.add(context);
	    			valid = mcbConfig.isValid(principal.getCurrentContexts(), clist);
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
					request.setAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY, matchedContexts.get(matchedContexts.size()-1));
					request.setAttribute(LoginHandler.PRINCIPAL_KEY, principal);
					AuthenticationEngine.returnToAuthenticationEngine(request, response);
					return true;
	    		}
	    		
				// -----------------------------
				
				// if there are no requested contexts, then the SP did not ask for one, so anything used is valid
				if (requestedContexts.size() == 0) {
					log.debug("No context requested for principal [{}]. Returning success.", principal.getName());
					// set the authentication context that was used
					principal.setCurrentContexts(usedContextList); // save the context values used
					// we must figure out if the user actually used a requested context or one that satisfied it by configuration
					if (validContexts.size() == 0) {
						request.setAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY, usedContextList.get(0));
					} else {
						// they used an upgraded one, we must send back the proper matching requested value, not what we used
						String ctx = mcbConfig.getUpgradedContext(usedContextList, requestedContexts);
						request.setAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY, ctx);
					}
					request.setAttribute(LoginHandler.PRINCIPAL_KEY, principal);
					request.setAttribute(LoginHandler.AUTHENTICATION_INSTANT_KEY, new DateTime());
					AuthenticationEngine.returnToAuthenticationEngine(request, response);
					return true;
				}
				// the user must re-authenticate with one of the requested contexts and its associated method
				log.debug("Principal [{}] must authenticate with a different context.", principal.getName());
				// check 4 -- does the user have a potential context that is on the requested list? if not, they fail always
				valid = mcbConfig.isValid(requestedContexts, potentialContexts);
				if (valid == false) {
					// user cannot authenticate with a requested context, return an error
					log.warn("Principal [{}] cannot satisfy requested authentication contexts for relying party [{}]", principal.getName(), entityID);
		        	AuthenticationException ae = new AuthenticationException("Principal unable to satisfy requested authentication contexts.");
		        	request.setAttribute(LoginHandler.AUTHENTICATION_EXCEPTION_KEY, ae);
		        	request.setAttribute(LoginHandler.AUTHENTICATION_ERROR_KEY, StatusCode.NO_AUTHN_CONTEXT_URI);
		        	request.removeAttribute(LoginHandler.PRINCIPAL_KEY);
		            AuthenticationEngine.returnToAuthenticationEngine(request, response);
		            return true;
				}
				
				// so the user must re-authenticate with a different context, there is one that meets the requirements
				userSession.setAttribute(UPGRADE_AUTH, Boolean.TRUE);
				showMethods(request, response, potentialContexts, requestedContexts);
				
				return false;
			}
			// if we get here then the login failed, we must count it and let the submodule handle the user retrying the login
			principal.setFailedCount( principal.getFailedCount() + 1 );
			log.debug("Current failed login count = [{}]", principal.getFailedCount());
			// only stop if we exceed the max failures and max failures is actually set
			if ((mcbConfig.getMaxFailures() != -1) && (principal.getFailedCount() >= mcbConfig.getMaxFailures())) {
				// reached the limit so generate an error
    			AuthenticationException ae = new AuthenticationException("Maximum login attempts reached.");
            	request.setAttribute(LoginHandler.AUTHENTICATION_EXCEPTION_KEY, ae);
            	// send them back with a SAML error
                AuthenticationEngine.returnToAuthenticationEngine(request, response);
                return true;
			}
			
			// set up our session variables
			userSession.setAttribute(PERFORM_AUTHENTICATION_PARAM_NAME, Boolean.TRUE);
			userSession.setAttribute(SELECTED_METHOD_PARAM_NAME, methodUsed);
			//userSession.setAttribute(CONTEXT_PARAM_NAME, contextUsed);
			
			b = sub.displayLogin(this, request, response);
			// must remove any attributes set for the submodule
			request.getSession().removeAttribute(MCBLoginServlet.FORCE_REAUTH);
			request.getSession().removeAttribute(MCBLoginServlet.UPGRADE_AUTH);
			log.debug("submodule display login returned [{}]", b);
			return true;
		} catch (UserInitiatedLoginFailureException uilfe) {
			// this is meant to capture an expected failure that ends the login cycle
			// it does not log at error level or generate a stack trace
			log.debug("User initiated login failure caught. {}",uilfe.getMessage());
			AuthenticationException ae = new AuthenticationException("User initiated login failure during authentication.");
        	request.setAttribute(LoginHandler.AUTHENTICATION_EXCEPTION_KEY, ae);
        	// send them back with a SAML error
            AuthenticationEngine.returnToAuthenticationEngine(request, response);
            return true;
		} catch (Exception e) {
			log.error("Exception calling submodule.", e);
			AuthenticationException ae = new AuthenticationException("Exception during authentication.");
        	request.setAttribute(LoginHandler.AUTHENTICATION_EXCEPTION_KEY, ae);
        	// send them back with a SAML error
            AuthenticationEngine.returnToAuthenticationEngine(request, response);
            return true;
		}
    }
    
    /**
     * Process the user's selection for authentication methods and send control to the proper submodule.
     * @param request
     * @param response
     * @param selectedMethodName
     * @return
     */
    protected boolean processSelectedMethod(HttpServletRequest request, HttpServletResponse response, String selectedMethodName) {
		log.debug("User selected authentication method to use of [{}]", selectedMethodName);
        HttpSession userSession = request.getSession();
		boolean pickedMethod = false;
		
		List<Method> methodList = (List<Method>) userSession.getAttribute(METHOD_LIST_PARAM_NAME);
		
		pickedMethod = validateSelectedMethod(selectedMethodName, methodList);
		
		if (pickedMethod == true) {
    		try {
				// if this is an upgrade authentication, but not a forced authentication and the user
				// has selected a previously used method, then just pass them through with that information
				Boolean bypassSatisfiedMethods = (Boolean) userSession.getAttribute(BYPASS_SATISFIED_METHODS);
				if (bypassSatisfiedMethods == null) bypassSatisfiedMethods = Boolean.FALSE;
				userSession.removeAttribute(BYPASS_SATISFIED_METHODS);
				log.debug("Bypass satisfied methods = [{}]", bypassSatisfiedMethods);
				if (bypassSatisfiedMethods.booleanValue() == true) {
					// see if the user chose a method they have already used, if so, bypass authentication
					MCBUsernamePrincipal principal = (MCBUsernamePrincipal) userSession.getAttribute(MCBLoginHandler.PRINCIPAL_KEY);
					Method method = mcbConfig.getMethodMap().get(selectedMethodName);
					for (String used: principal.getCurrentContexts()) {
						log.debug("Used context = [{}] -- Selected method = [{}]", used, method.getName());
						ArrayList<String> contextList = mcbConfig.getContextFromMethod(selectedMethodName);
						for (String context: contextList) {
							if (used.equals(context) == true) {
								// winner, winner, chicken dinner
								log.debug("User selected prior method, bypassing re-authentication and using context [{}}", used);
				    			userSession.removeAttribute(MCBLoginServlet.FORCE_REAUTH);
				    			userSession.removeAttribute(MCBLoginServlet.UPGRADE_AUTH);
	
								request.setAttribute(LoginHandler.AUTHENTICATION_METHOD_KEY, used);
								request.setAttribute(LoginHandler.PRINCIPAL_KEY, principal);
								AuthenticationEngine.returnToAuthenticationEngine(request, response);
								return true;
							}
						}
					}
				}
			
			
				// The user has selected a valid method/context, so next we must ask that method
				// to display a login form for the user
				Method method = mcbConfig.getMethodMap().get(selectedMethodName);
				MCBSubmodule sub = mcbConfig.getSubmoduleMap().get(method.getBean());
				log.debug("Using submodule with bean name of [{}]", method.getBean());
				// set up our session variables
				userSession.setAttribute(SUBMODULE_PARAM_NAME, sub); // store the submodule we used
				userSession.setAttribute(SELECTED_METHOD_PARAM_NAME, selectedMethodName);
				userSession.setAttribute(PERFORM_AUTHENTICATION_PARAM_NAME, Boolean.TRUE);
				//userSession.setAttribute(CONTEXT_PARAM_NAME, contextUsed);

				boolean b = sub.displayLogin(this, request, response);
				// must remove any attributes we sent to the submodule
    			request.getSession().removeAttribute(MCBLoginServlet.FORCE_REAUTH);
    			request.getSession().removeAttribute(MCBLoginServlet.UPGRADE_AUTH);
				log.debug("submodule display login returned [{}]", b);
				return true;
    		} catch (Exception e) {
    			log.error("Exception calling submodule with method name of [{}]", selectedMethodName);
				log.error("Exception calling submodule.", e);
    			AuthenticationException ae = new AuthenticationException("Exception during authentication.");
            	request.setAttribute(LoginHandler.AUTHENTICATION_EXCEPTION_KEY, ae);
            	// send them back with a SAML error
                AuthenticationEngine.returnToAuthenticationEngine(request, response);
                return true;
    		}
		} else {
			log.warn("User submitted an invalid method name of [{}]", selectedMethodName);
		}
		return false;

    }
    
    /**
     * Based on configuration, either show the list of methods for the user to choose from or display the login for
     * that method if there is only one, or only one by configuration.
     * @param request
     * @param response
     */
    protected void showMethods(HttpServletRequest request, HttpServletResponse response) {
        HttpSession userSession = request.getSession();

        log.debug("Showing methods available based on configuration.");
		// So at this point, either this is the first leg or the user has tried to submit a non-permitted method name
    	// check and see what our default behavior is
    	if (mcbConfig.isShowOnlyRequested() == true) {
    		log.debug("showing only requested contexts");
    		List<String> requestedContexts = getRequestedContexts(request);
    		
    		// we need to build the list of requested contexts to show the user
    		List<Method> allMethods = new ArrayList<Method>();
    		for (String contextName: requestedContexts) {
    			String methodName = mcbConfig.getContextMap().get(contextName).getMethod();
    			String methodLabel = mcbConfig.getMethodMap().get(methodName).getContent();
    			Method method = mcbConfig.getMethodMap().get(methodName);
    			allMethods.add(method);
    			log.trace("Adding method [{}]", methodLabel);
    		}

    		// filter the list
    		allMethods = mcbConfig.getUniqueMethods(allMethods);

			// if no methods remain after filtering based on the requested values, then use all values
    		if (allMethods.size() == 0) {
    			log.debug("No methods remained after filtering. Add all default choices back to list. [{}]", mcbConfig.getDefaultMethodList().size());
    			allMethods.addAll(mcbConfig.getDefaultMethodList());
    			log.debug("allMethods.size = [{}]", allMethods.size());
    		}
    		
    		// if only a single method, then we need to use that one
    		if (allMethods.size() == 1) {
    			try {
	    			Method method = allMethods.get(0);
	    			MCBSubmodule sub = mcbConfig.getSubmoduleMap().get(method.getBean());
	    			log.debug("Using submodule with bean name of [{}]", method.getBean());
					// set up our session variables
					userSession.setAttribute(SUBMODULE_PARAM_NAME, sub); // store the submodule we used
					userSession.setAttribute(SELECTED_METHOD_PARAM_NAME, method.getName());
					userSession.setAttribute(PERFORM_AUTHENTICATION_PARAM_NAME, Boolean.TRUE);
					
	    			boolean b = sub.displayLogin(this, request, response);
	    			// must remove any attributes we sent to the submodule
	    			request.getSession().removeAttribute(MCBLoginServlet.FORCE_REAUTH);
	    			request.getSession().removeAttribute(MCBLoginServlet.UPGRADE_AUTH);
					log.debug("submodule returned [{}]", b);
	    			return;
    			} catch (Exception e) {
    				log.error("Exception calling submodule.", e);
        			AuthenticationException ae = new AuthenticationException("Exception during authentication.");
                	request.setAttribute(LoginHandler.AUTHENTICATION_EXCEPTION_KEY, ae);
                	// send them back with a SAML error
                    AuthenticationEngine.returnToAuthenticationEngine(request, response);
                    return;
    			}
    			
    		}
    		
    		try {
	    		VelocityContext vCtx = new VelocityContext();
	    		vCtx.put("methodList", allMethods);
	    		userSession.setAttribute(METHOD_LIST_PARAM_NAME, allMethods);
	    		doVelocity(request, response, "selectcontext.vm", vCtx);
    		} catch (AuthenticationException ae) {
    			log.error("", ae);
            	request.setAttribute(LoginHandler.AUTHENTICATION_EXCEPTION_KEY, ae);
            	// send them back with a SAML error
                AuthenticationEngine.returnToAuthenticationEngine(request, response);
                return;
    		}

    		return;
    	} else {
    		log.debug("Showing only default contexts from configuration.");
    		
    		// if only a single method, then we need to use that one
    		if (mcbConfig.getDefaultMethodList().size() == 1) {
    			try {
	    			Method method = mcbConfig.getDefaultMethodList().get(0);
	    			MCBSubmodule sub = mcbConfig.getSubmoduleMap().get(method.getBean());
	    			log.debug("Using submodule with bean name of [{}]", method.getBean());
					// set up our session variables
					userSession.setAttribute(SUBMODULE_PARAM_NAME, sub); // store the submodule we used
					userSession.setAttribute(SELECTED_METHOD_PARAM_NAME, method.getName());
					userSession.setAttribute(PERFORM_AUTHENTICATION_PARAM_NAME, Boolean.TRUE);
					
	    			boolean b = sub.displayLogin(this, request, response);
	    			// must remove any attributes we set for the submodule
	    			request.getSession().removeAttribute(MCBLoginServlet.FORCE_REAUTH);
	    			request.getSession().removeAttribute(MCBLoginServlet.UPGRADE_AUTH);
					log.debug("submodule returned [{}]", b);
	    			return;
    			} catch (Exception e) {
    				log.error("Exception calling submodule.", e);
        			AuthenticationException ae = new AuthenticationException("Exception during authentication.");
                	request.setAttribute(LoginHandler.AUTHENTICATION_EXCEPTION_KEY, ae);
                	// send them back with a SAML error
                    AuthenticationEngine.returnToAuthenticationEngine(request, response);
                    return;
    			}
    			
    		}

    		// more than one context list, show all the methods
    		try {
	    		VelocityContext vCtx = new VelocityContext();
	    		userSession.setAttribute(METHOD_LIST_PARAM_NAME, mcbConfig.getDefaultMethodList());
	    		vCtx.put("methodList", mcbConfig.getDefaultMethodList());
	    		doVelocity(request, response, "selectcontext.vm", vCtx);
    		} catch (AuthenticationException ae) {
    			log.error("", ae);
            	request.setAttribute(LoginHandler.AUTHENTICATION_EXCEPTION_KEY, ae);
            	// send them back with a SAML error
                AuthenticationEngine.returnToAuthenticationEngine(request, response);
                return;
    		}
    		return;
    	}

    	
    }

    /**
     * This version of showMethods is used after a user has done an initial authentication and has been identified.
     * @param request
     * @param response
     * @param potentialContexts The list of context values the idms has listed for the user.
     * @param requestedContexts The list of context values the SP has requested.
     */
    protected void showMethods(HttpServletRequest request, HttpServletResponse response, 
    		List<String> potentialContexts, List<String> requestedContexts) {
        HttpSession userSession = request.getSession();
    	MCBUsernamePrincipal principal = (MCBUsernamePrincipal) userSession.getAttribute(LoginHandler.PRINCIPAL_KEY);
    	// if force authentication is requested, always show all choices
    	Boolean forceAuth =  (Boolean) userSession.getAttribute(FORCE_REAUTH);
    	if (forceAuth == null) forceAuth = Boolean.FALSE;
    	log.debug("Force reauth = [{}]", forceAuth);
    	
        // get the total list of contexts that can satisfy
        ArrayList<String> allowableContexts = mcbConfig.getSatisfyingContexts(potentialContexts, requestedContexts);
        log.debug("Found [{}] allowable contexts to choose from.", allowableContexts.size());
		// we need to build the list of allowable methods to show the user based on the allowable contexts
		List<Method> allMethods = new ArrayList<Method>();
		for (String contextName: allowableContexts) {
			String methodName = mcbConfig.getContextMap().get(contextName).getMethod().trim();
			String methodLabel = mcbConfig.getMethodMap().get(methodName).getContent().trim();
			Method method = mcbConfig.getMethodMap().get(methodName);
			method.setSatisfied(false); // initially false
			for (String used: principal.getCurrentContexts()) {
				if (contextName.equals(used) == true) {
					method.setSatisfied(true); // override to true
					log.debug("Found previously satisfied context of [{}]", contextName);
				}
			}
			// if configuration says to show all or force authentication is requested, always show the values
			if ((mcbConfig.isShowSatisfiedContexts() == true) || (forceAuth.booleanValue() == true)) {
				allMethods.add(method);
				log.trace("Adding method [{}]", methodLabel);
			} else if (method.isSatisfied() == false) {
				allMethods.add(method);
				log.trace("Adding method [{}]", methodLabel);
			} else {
				log.debug("Skipping method [{}] due to excluding already satisfied context values.", methodLabel);
			}
		}

		if (requestedContexts.size() == 0) {
			// The SP did not request any context, so use the potential context list for this user
			log.debug("Relying party did not request a context, using potential context list for the user.");
			for (String contextName: potentialContexts) {
				log.trace("Looking up method for context name = [{}]", contextName);
				try {
					String methodName = mcbConfig.getContextMap().get(contextName).getMethod().trim();
					String methodLabel = mcbConfig.getMethodMap().get(methodName).getContent().trim();
					Method method = mcbConfig.getMethodMap().get(methodName);
					allMethods.add(method);
					log.trace("Adding method [{}]", methodLabel);
				} catch (NullPointerException npe) {
					log.warn("Method for requested context [{}] NOT found in configuration.", contextName);
				}
			}
		}
		
		// filter the list
		allMethods = mcbConfig.getUniqueMethods(allMethods);
		
		// if there are no satisfying authentication methods defined here, we return an error to the SP
		if (allMethods.size() == 0) {
			log.warn("Unable to satisfy requested authentication context of [{}]. Returning SAML error to SP.", requestedContexts);
			AuthenticationException ae = new AuthenticationException("Unable to satisfy requested authentication context.");
        	request.setAttribute(LoginHandler.AUTHENTICATION_EXCEPTION_KEY, ae);
        	// send them back with a SAML error
            AuthenticationEngine.returnToAuthenticationEngine(request, response);
            return;
		}
		// if only a single method, then we need to use that one
		if (allMethods.size() == 1) {
			try {
    			Method method = allMethods.get(0);
    			MCBSubmodule sub = mcbConfig.getSubmoduleMap().get(method.getBean());
    			log.debug("Using submodule with bean name of [{}]", method.getBean());
				// set up our session variables
				userSession.setAttribute(SUBMODULE_PARAM_NAME, sub); // store the submodule we used
				userSession.setAttribute(SELECTED_METHOD_PARAM_NAME, method.getName());
				userSession.setAttribute(PERFORM_AUTHENTICATION_PARAM_NAME, Boolean.TRUE);
    			
    			boolean b = sub.displayLogin(this, request, response);
    			// must remove any attributes set for the submodule
    			request.getSession().removeAttribute(MCBLoginServlet.FORCE_REAUTH);
    			request.getSession().removeAttribute(MCBLoginServlet.UPGRADE_AUTH);
				userSession.setAttribute(SUBMODULE_PARAM_NAME, sub); // store the submodule we used
				log.debug("submodule returned [{}]", b);
    			return;
			} catch (Exception e) {
				log.error("Exception calling submodule.", e);
    			AuthenticationException ae = new AuthenticationException("Exception during authentication.");
            	request.setAttribute(LoginHandler.AUTHENTICATION_EXCEPTION_KEY, ae);
            	// send them back with a SAML error
                AuthenticationEngine.returnToAuthenticationEngine(request, response);
                return;
			}
			
		}

		// display the list of allowable methods
		try {
			VelocityContext vCtx = new VelocityContext();
			vCtx.put("methodList", allMethods);
    		userSession.setAttribute(METHOD_LIST_PARAM_NAME, allMethods);
			// note that this is an upgrade authentication request
			Boolean upgradeAuth = (Boolean) userSession.getAttribute(UPGRADE_AUTH);
			if (upgradeAuth == null) upgradeAuth = Boolean.FALSE;
			userSession.removeAttribute(UPGRADE_AUTH);
			if (upgradeAuth.booleanValue() == true) {
				vCtx.put("upgradeAuth","true");
			} else {
				vCtx.put("upgradeAuth","");
			}
			// note that this is an force re-authentication request
//			Boolean forceAuth = (Boolean) userSession.getAttribute(FORCE_REAUTH);
			userSession.removeAttribute(FORCE_REAUTH);
			if (forceAuth.booleanValue() == true) {
				vCtx.put("forceAuth","true");
			} else {
				vCtx.put("forceAuth","");
			}

			if ((upgradeAuth.booleanValue() == true) && (forceAuth.booleanValue() == false)) {
				log.debug("Setting bypass satisfied to true.");
				userSession.setAttribute(BYPASS_SATISFIED_METHODS, new Boolean(Boolean.TRUE));
			}
			doVelocity(request, response, "selectcontext.vm", vCtx);
		} catch (AuthenticationException ae) {
			log.error("", ae);
			request.setAttribute(LoginHandler.AUTHENTICATION_EXCEPTION_KEY, ae);
			// send them back with a SAML error
			AuthenticationEngine.returnToAuthenticationEngine(request, response);
			return;
		}
    }
    
    /**
     * Get the list of requested contexts excluding the "unspecified" one.
     * @param request The HTTP request.
     * @return A list of contexts. Could be empty.
     */
    private List<String> getRequestedContexts(HttpServletRequest request) {
    	ServletContext application = null;
    	LoginContext loginContext = null;
    	EntityDescriptor entityDescriptor = null;
    	String entityID = null;

		application = this.getServletContext();
		loginContext = (LoginContext)HttpServletHelper.getLoginContext(HttpServletHelper.getStorageService(application),
				application, request);
		entityDescriptor = HttpServletHelper.getRelyingPartyMetadata(loginContext.getRelyingPartyId(),
				HttpServletHelper.getRelyingPartyConfigurationManager(application));
		entityID = entityDescriptor.getEntityID();
		log.debug("Getting requested contexts for relying party = [{}]", entityID);
		List<String> requestedContexts = loginContext.getRequestedAuthenticationMethods();
		// we must remove the "unspecified" context, it has no meaning as a requested context
		if (requestedContexts != null) {
			for (String ctx: requestedContexts) {
				if (ctx.equals(AuthnContext.UNSPECIFIED_AUTHN_CTX) == true) {
					log.warn("Relying party [{}] requested the unspecified authncontext value. Removing.", entityID);
					requestedContexts.remove(ctx);
				}
			}
		}
		
		return requestedContexts;
    }
    
    
    /**
     * Helper method for submodules to display a login form using Velocity templates.
     * 
     * @param request HTTP request.
     * @param response HTTP response.
     * @param templateName The template name to use.
     * @param vCtx A velocity context to bind to the template.
     * @throws AuthenticationException
     */
    public void doVelocity(HttpServletRequest request, HttpServletResponse response, String templateName, VelocityContext vCtx) throws AuthenticationException {
        vCtx.put("actionUrl", request.getContextPath() + request.getServletPath());
		
        IDPUIHandler vHandler = new IDPUIHandler(request, getServletContext());

        //insert the UI elements
        vCtx.put("UILogo", vHandler.getServiceLogo());
        vCtx.put("UIDescription", vHandler.getServiceDescription());
        vCtx.put("UIName", vHandler.getServiceName());
        vCtx.put("UIPrivacyURL", vHandler.getPrivacyURL());
        vCtx.put("UIInfoURL", vHandler.getInformationURL());
        vCtx.put("UIEntityID", vHandler.getEntityID());

        response.setContentType("text/html");
        response.setHeader("Cache-Control", "content=\"no-store,no-cache,must-revalidate\"");
        response.setHeader("Pragma","no-cache");
        response.setHeader("Expires","-1");
        
        try {
        	log.debug("Displaying velocity template of [{}]", templateName);
            Template template = velocity.getTemplate(templateName);
            PrintWriter writer = response.getWriter();
            template.merge(vCtx, writer);
            writer.flush();
        } catch (Exception e) {
            log.error("", e);
            throw new AuthenticationException("Error while processing login template.", e);
        }

        return;
    }
    
    /**
     * Validate that the method returned by the selection page (from the end user) is actually permitted
     * to be selected.
     * @param selectedMethod The method as selected by the user on the selection page.
     * @param requestedContexts The list of context values requested by the RP
     * @return true if the method is allowed to be used
     */
    protected boolean validateSelectedContext(String selectedMethod, List<String> requestedContexts) {
    	boolean selectedIsOk = false;

    	// it is possible for there to be requested context values but none of them were
    	// on the default list, so the value chosen by the user would never be on the list for
    	// them to select. So we either need to keep track of that fact in state or just always
    	// validate against the complete initial list of methods.
    	if ((mcbConfig.isShowOnlyRequested() == true) && (requestedContexts.size() > 0)) {
    		log.debug("Validating selected against requested contexts");

    		// first take the requested context values and find the matching method
    		for (String contextName: requestedContexts) {
    			String methodName = mcbConfig.getContextMap().get(contextName).getMethod();
    			
    			if (methodName.equals(selectedMethod) == true) {
    				// we found a permitted match
    				return true;
    			}
    		}

    	} else {
    		log.debug("Validating selected against all default contexts");
    		for (String ctx: mcbConfig.getDefaultContextList()) {
    			String methodName = mcbConfig.getContextMap().get(ctx).getMethod();
       			if (methodName.equals(selectedMethod) == true) {
    				// we found a permitted match
    				return true;
       			}
    		}
    	}
    	// Note that the other configuration option is to use a default context. If that option
    	// is set, then we should never get into this method, so we will default to false.
    	
    	return selectedIsOk;
    }
    
    protected boolean validateSelectedMethod(String selectedMethod, List<Method> methodList) {

    	for (Method method: methodList) {
    		if (method.getName().equalsIgnoreCase(selectedMethod) == true) {
    			return true;
    		}
    	}
    	return false;
    }
    
    
    /**
     * Send the user to the login page to display a way to login
     * 
     * @param request
     * @param response
     * @param queryParams
     * @param currentLoginPage
     */
    protected void redirectToSelectContextPage(HttpServletRequest request, HttpServletResponse response,
            List<Pair<String, Object>> queryParams, String currentLoginPage) {
    	
        String requestContext = DatatypeHelper.safeTrimOrNullString(request.getContextPath());
        if(requestContext == null){
            requestContext = "/";
        }
        request.setAttribute("actionUrl", requestContext + request.getServletPath());
        log.debug("actionUrl = [{}]", requestContext + request.getServletPath());
        if(queryParams != null){
            for(Pair<String, Object> param : queryParams){
                request.setAttribute(param.getFirst(), param.getSecond());
                log.trace("Setting attribute [{}] = [{}]", param.getFirst(), param.getSecond());
            }
        }
        
        try {
        	// forward this request internally to the actual jsp login page we need
        	request.getRequestDispatcher(currentLoginPage).forward(request, response);
            log.debug("Redirecting to select context page [{}]", currentLoginPage);
        } catch (IOException ex) {
            log.error("Unable to redirect to select context page.", ex);
        }catch (ServletException ex){
            log.error("Unable to redirect to select context page.", ex);            
        }
    }

    
    /**
     * Send the user to the login page to display a way to login
     * 
     * @param request
     * @param response
     * @param queryParams
     * @param currentLoginPage
     */
    public void redirectToLoginPage(HttpServletRequest request, HttpServletResponse response,
            List<Pair<String, Object>> queryParams, String currentLoginPage) {
    	
        String requestContext = DatatypeHelper.safeTrimOrNullString(request.getContextPath());
        if(requestContext == null){
            requestContext = "/";
        }
        request.setAttribute("actionUrl", requestContext + request.getServletPath());
        log.debug("actionUrl = [{}]", requestContext + request.getServletPath());
        if(queryParams != null){
            for(Pair<String, Object> param : queryParams){
                request.setAttribute(param.getFirst(), param.getSecond());
                log.trace("Setting attribute [{}] = [{}]", param.getFirst(), param.getSecond());
            }
        }
        
        try {
        	// forward this request internally to the actual jsp login page we need
        	request.getRequestDispatcher(currentLoginPage).forward(request, response);
            log.debug("Redirecting to login page [{}]", currentLoginPage);
        } catch (IOException ex) {
            log.error("Unable to redirect to login page.", ex);
        }catch (ServletException ex){
            log.error("Unable to redirect to login page.", ex);            
        }
    }

}
