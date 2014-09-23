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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.servlet.ServletContext;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.assurance.mcb.config.AllowPrincipalSwitchingEnumType;
import edu.internet2.middleware.assurance.mcb.config.AllowedContexts;
import edu.internet2.middleware.assurance.mcb.config.AuthMethods;
import edu.internet2.middleware.assurance.mcb.config.Context;
import edu.internet2.middleware.assurance.mcb.config.Method;
import edu.internet2.middleware.assurance.mcb.config.MultiContextBroker;
import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;

/**
 * Read and represent in memory the Multi-Context Broker configuration file. Also
 * includes many utility methods to determine which path and options to show to the
 * end user as they authenticate.
 * 
 * @author Paul Hethmon
 *
 */
public class MCBConfiguration {
	
	/** Class logger. */
    private final Logger log = LoggerFactory.getLogger(MCBConfiguration.class);

    /**
     * private class to hold the graphed contexts
     *
     */
	private class ContextGraph {
		public String name = null;
		public ArrayList<ContextGraph> allowed = null;
		
		public ContextGraph(String name) {
			this.name = name;
			allowed = new ArrayList<ContextGraph>();
		}
		
		public boolean matchContext(String context) {
			// simple case
			if (name.equals(context) == true) {
				return true;
			}
			
			// simple failed, check for children
			for (ContextGraph child: allowed) {
				// see if their is a match at the child level
				if (child.matchContext(context) == true) {
					return true;
				}
			}
			
			return false;
		}
	}

	private class MethodToContext {
		public String method;
		public ArrayList<String> contextList;
		
		public MethodToContext() {
			method = null;
			contextList = new ArrayList<String>();
		}
	}
	
	// JAXB parser
    private static final JAXBContext jaxbContext = initContext();
    // Make a static so we only take the initialization hit once per jvm
    private static JAXBContext initContext() {
        try {
            // create a JAXBContext capable of handling classes generated into
            // the edu.internet2.middleware.assurance.mcb.config package
			return JAXBContext.newInstance("edu.internet2.middleware.assurance.mcb.config", MCBConfiguration.class.getClassLoader());
		} catch (JAXBException e) {
			e.printStackTrace();
			return null;
		}
    }

    // Maps of various data elements we use
    private HashMap<String, MCBSubmodule> submoduleMap = null;
    private HashMap<String, Method> methodMap = null;
    private HashMap<String, Context> contextMap = null;
    private HashMap<String, ContextGraph> graphMap = null;
    private HashMap<String, MethodToContext> methodToContextMap = null;
    private ArrayList<String> defaultContextList = null;
    private ArrayList<Method> defaultMethodList = null;
    
	// show only auth methods that match the requested (if any match)
	private boolean showOnlyRequested = false;
	// show satisfied contexts when upgrade authentication is needed
	private boolean showSatisfiedContexts = false;
	// How many failures are allowed before sending a SAML failure back to the RP
	private int maxFailures = -1;
	// The velocity properties file
	private String velocityPropertiesFile = null;
	// The attribute resolver ID value
	private String attributeResolverID = null;
	// Do we require a user to have an assigned context. If we do not require it
	// and the RP did not request a context, then authentication can succeed. If the
	// RP requires a context, we always enforce the principal having one.
	private boolean principalAuthnContextRequired = true;
	
	public enum AllowPrincipalSwitching {
		NONE,
		CASE_ONLY,
		ANY
	}
	private AllowPrincipalSwitching allowPrincipalSwitching = null;
	
	
	public MCBConfiguration(String configurationFile, Collection<MCBSubmodule> beans) throws Exception {

		// The list of submodules
		submoduleMap = new HashMap<String, MCBSubmodule>();
		// load the beans into a map
		for (MCBSubmodule sub: beans) {
			log.debug("Loading submodule [{}]", sub.getBeanName());
			submoduleMap.put(sub.getBeanName(), sub);
			sub.init();
		}
		
		defaultContextList = new ArrayList<String>();
		
        // create an Unmarshaller
        Unmarshaller u;
		try {
			u = jaxbContext.createUnmarshaller();
        
	        // unmarshal a MultiContextBroker instance document into a tree of Java content
	        // objects composed of classes from the com.clareity.jaguar.config package.
	        MultiContextBroker mcb = (MultiContextBroker)u.unmarshal( new FileInputStream( configurationFile ) );

	        // Check and see what option the administrator has chosen for us to use
	        // during initial login
	        if ((mcb.getInitialAuthContext().isRequestedOnly() != null) && (mcb.getInitialAuthContext().isRequestedOnly().booleanValue() == true)){
	        	showOnlyRequested = true;
	        	log.info("MCB using only requested contexts for initial login choices.");
	        } else {
	        	showOnlyRequested = false;
	        }
        	List<Context> ctxList = mcb.getInitialAuthContext().getContext();
        	for (Context ctx: ctxList) {
        		defaultContextList.add(ctx.getName());
        	}
        	log.info("MCB using a default context list of [{}] for initial login.", defaultContextList.size());
	        
	        setVelocityPropertiesFile(mcb.getVelocityPropertiesFile());
	        
	        setPrincipalAuthnContextRequired(mcb.isPrincipalAuthnContextRequired());
	        log.info("MCB principalAuthnContextRequired = [{}]", isPrincipalAuthnContextRequired());
	        
	        if (mcb.isShowSatisfiedContexts() != null) {
	        	setShowSatisfiedContexts(mcb.isShowSatisfiedContexts());
	        }
	        log.info("MCB showSatisifiedContexts = [{}]", isShowSatisfiedContexts());
	        
	        
	        if (mcb.getAllowPrincipalSwitching() != null) {
	        	if (mcb.getAllowPrincipalSwitching() == AllowPrincipalSwitchingEnumType.ANY) {
	        		setAllowPrincipalSwitching(AllowPrincipalSwitching.ANY);
	        	} else if (mcb.getAllowPrincipalSwitching() == AllowPrincipalSwitchingEnumType.CASE_ONLY) {
	        		setAllowPrincipalSwitching(AllowPrincipalSwitching.CASE_ONLY);
	        	} else if (mcb.getAllowPrincipalSwitching() == AllowPrincipalSwitchingEnumType.NONE) {
	        		setAllowPrincipalSwitching(AllowPrincipalSwitching.NONE);
	        	}
	        	log.info("Allow principal switching set to [{}]", allowPrincipalSwitching);
	        } else {
	        	setAllowPrincipalSwitching(AllowPrincipalSwitching.CASE_ONLY);
	        	log.warn("Allow principal switching set to default value [{}]", allowPrincipalSwitching);
	        }
	        
	        maxFailures = mcb.getMaxFailures();
	        log.info("MCB setting max failures to [{}]", maxFailures);

	        // Used to determine which authentication contexts a user is allowed
	        attributeResolverID = mcb.getIdms().getAttributeResolverID();
	        log.info("Using [{}] for attribute-resolver ID value.", attributeResolverID);
	        
	        // read in the auth context information
	        contextMap = new HashMap<String, Context>();
	        for (Context context: mcb.getAuthnContexts().getContext()) {
	        	contextMap.put(context.getName(), context);
	        }
	        // now that we have the base data, let's create our graph structure
	        // that represents the actual usage
	        graphMap = new HashMap<String, ContextGraph>();
	        Set<String> keys = contextMap.keySet();
	        Iterator<String> it = keys.iterator();
	        while (it.hasNext() == true) {
	        	String contextKey = it.next();
	        	Context context = contextMap.get(contextKey);

	        	log.info("Adding top level node of [{}]", context.getName());
	        	ContextGraph cg = addNode(context);
	        	graphMap.put(cg.name, cg);
	        	log.info("");
	        }
	        
	        // now validate that there are no circular references
	        keys = contextMap.keySet();
	        it = keys.iterator();
	        while (it.hasNext() == true) {
	        	String contextKey = it.next();
	        	Context context = contextMap.get(contextKey);

	        	log.info("Checking top level node of [{}]", context.getName());
	        	ArrayList<String> container = new ArrayList<String>();
	        	container.add(context.getName());
	        	ArrayList<String> contextList = this.getSatisfyingContexts(container);
	        	if (contextList == null) {
	        		log.error("Invalid configuration starting with context node of [{}]. Check for circular references.", context.getName());
	        		throw new Exception("Invalid configuration starting with context node of [" + context.getName() + "]. Check for circular references.");
	        	}
	        }
	        
	        // Create a map of the methods available to the auth contexts they represent
	        methodToContextMap = new HashMap<String, MethodToContext>();
	        methodMap = new HashMap<String, Method>();
	        // First get the methods we support for authentication
	        for (Method method: mcb.getAuthMethods().getMethod()) {
	        	methodMap.put(method.getName(), method);
	        	// add this method to our method to context map as well
	        	MethodToContext mtc = new MethodToContext();
	        	mtc.method = method.getName();
	        	methodToContextMap.put(mtc.method, mtc);
	        }
	        
	        // Now attach the context names to the methods we have
	        for (String key: contextMap.keySet()) {
	        	Context ctx = contextMap.get(key);
	        	MethodToContext mtc = methodToContextMap.get(ctx.getMethod());
	        	mtc.contextList.add(ctx.getName());
	        	log.debug("Adding context [{}] to method [{}]", ctx.getName(), mtc.method);
	        }
	        
	        // just to verify we have loaded what we think we have
	        if (log.isDebugEnabled() == true) {
	        	for (String key: methodToContextMap.keySet()) {
	        		StringBuilder sb = new StringBuilder();
	        		MethodToContext mtc = methodToContextMap.get(key);
	        		sb.append("Method = [" + mtc.method + "] --");
	        		for (String ctx: mtc.contextList) {
	        			sb.append("  Context = [" + ctx + "]");
	        		}
		        	log.debug(sb.toString());
	        	}
	        }
	        
    		log.debug("Building the default initial authentication method list.");
    		// we need to build the list of requested contexts to show the user
    		// first put in a hash table to eliminate any duplicates
    		Hashtable<String, Method> methodHash = new Hashtable<String, Method>();
    		for (String contextName: getDefaultContextList()) {
    			String methodName = getContextMap().get(contextName).getMethod();
    			//String methodLabel = getMethodMap().get(methodName).getContent();
    			Method method = getMethodMap().get(methodName);
    			methodHash.put(methodName, method);
    		}
    		// now iterate through the hash and put them in our array list
    		defaultMethodList = new ArrayList<Method>();

    		// Now we must preserve the order of the configuration
    		for (String ctx: getDefaultContextList()) {
    			String methodName = getContextMap().get(ctx).getMethod();
    			log.debug("Checking for [{}] in methodHash", methodName.trim());
    			if (methodHash.containsKey(methodName) == true) {
    				log.trace("Adding context [{}] to ordered list.", ctx);
    				Method m = methodHash.get(methodName);
    				defaultMethodList.add(m);
        			log.debug("Adding default method [{}]", m.getContent());
    				methodHash.remove(methodName);
    			}
    		}

		} catch (JAXBException e) {
			log.error("", e);
		} catch (FileNotFoundException e) {
			log.error("", e);
		}

	}
	
	/**
	 * Filter the list of methods down to the unique list.
	 * @param methodList
	 * @return
	 */
	public List<Method> getUniqueMethods(List<Method> methodList) {
		Hashtable<String, Method> methodHash = new Hashtable<String, Method>();
		ArrayList<Method> newMethodList = new ArrayList<Method>();
		for (Method m: methodList) {
			// if the hash did not have an item of this name, then this is a unique item
			if (methodHash.put(m.getName(), m) == null) {
				// so add it to our final list, only unique items will be added here
				newMethodList.add(m);
			}
		}
		return newMethodList;
	}
	
	
	
	/**
	 * Get the list of contexts that this method satisfies.
	 * 
	 * @param method The method used.
	 * @return A list of context values or null.
	 */
	public ArrayList<String> getContextFromMethod(String method) {
		MethodToContext mtc = methodToContextMap.get(method);
		if (mtc != null) {
			log.trace("mtc = [{}]", mtc.method);
            //since this class is statically instantiated, ensure this 
            //method returns a new object rather than a link to the static one
            //so that manipulations to the list do not get saved globally
            ArrayList<String> returnMe = new ArrayList<String>();
            for(String aString:mtc.contextList){
                returnMe.add(new String(aString));
            }
			return returnMe;
		}
		
		return null;
	}
	
	/**
	 * Return true if any of the values in the source list are in the container.
	 * 
	 * @param source A list of contet values
	 * @param container A list of context values
	 * @return true if any value in source is in container
	 */
	public boolean isValid(List<String> source, List<String> container) {
		
		for (String ctx: source) {
			log.trace("Looking for value [{}] in list.", ctx);
			if (container.contains(ctx) == true) {
				log.trace("Found value [{}] in list.", ctx);
				return true;
			}
		}
		
		return false;
	}

	/**
	 * Get the list of context values that satisfy the source contexts based on what is in the container
	 * list and child contexts that are also allowed for that context.
	 * @param source The list of context values we need to satisfy.
	 * @param container The base list of context values we are going to search.
	 * @param returnAllContexts If true, return any context that can satisfy. If false, only exact matches.
	 * @return The list that satisfies.
	 */
	public ArrayList<String> getSatisfyingContexts(List<String> source, List<String> container) {
		ArrayList<String> ordered = new ArrayList<String>();

		if (log.isTraceEnabled() == true) {
			for (String src: source) {
				log.trace("Source context: [{}]", src);
			}
			for (String ctn: container) {
				log.trace("Container context: [{}]", ctn);
			}
		}

		// Now we must preserve the order of the RP based on what satisfies their request
		// container is the correct order, so if the item in the container is in the satisfyWithChildren list,
		// we keep it
		for (String ctx: container) {
			// so this ctx value matches a value that satisfies the container. we must
			// now find a context value from the source list that is either an exact match or
			// can satisfy the ctx value
			if (source.contains(ctx) == true) {
				log.trace("Adding direct context [{}] to ordered list.", ctx);
				ordered.add(ctx);
			} else {
				log.trace("Looking for context [{}] to be satisfied by a higher level context.", ctx);
				// find the member of the source list that can satisfy ctx
				ArrayList<String> tmpList = new ArrayList<String>();
				tmpList.add(ctx);
				ArrayList<String> ctxList = getSatisfyingContexts(tmpList);
				// ctxList is the list of context values that can be substitued per configuration for ctx
				for (String src: source) {
					// so for each value in the src list, see if we can add it. Only if its in the ctxLit
					// and it's not already in the ordered list (no dupes)
					if ((ctxList.contains(src) == true) && (ordered.contains(src) == false)) {
						log.trace("Adding context [{}] to ordered list.", src);
						ordered.add(src);
					}
				}
			}
		}

		log.trace("Returning ordered list with [{}] elements.", ordered.size());
		return ordered;
	}
	
	/**
	 * Get the list of contexts and their children based on the given list.
	 * @param container
	 * @return
	 */
	public ArrayList<String> getSatisfyingContexts(List<String> container) {
		ArrayList<String> containerWithChildren = new ArrayList<String>();
		
		try {
			// we first need to iterate the container to find all the children
			for (String ctx: container) {
				log.trace("  Adding context of [{}]", ctx);
				containerWithChildren.add(ctx);
				ArrayList<String> children = getGraphChildren(ctx);
				if (children != null) {
					for (String child: children) {
						if (containerWithChildren.contains(child) == false) {
							containerWithChildren.add(child);
						}
					}
					//containerWithChildren.addAll(children);
				}
			}
		} catch (StackOverflowError e) {
			log.error("Exception while iterating over context graph.", e);
			return null;
		}
		
		// print out the contents
		if (log.isTraceEnabled() == true) {
			for (String ctx: containerWithChildren) {
				log.trace(" containerWithChildren [{}]", ctx);
			}
		}
		return containerWithChildren;
	}

	/**
	 * Get the higher level context that was used to satisfy the lower level context which was requested by the SP.
	 * @param usedContextList  The list of authentication contexts used.
	 * @param requestedContextList  The list of authentication contexts requested by the SP.
	 * @return
	 */
	public String getUpgradedContext(List<String> usedContextList, List<String> requestedContextList) {
		
		try {
			// we first need to iterate the container to find all the children
			for (String ctx: usedContextList) {
				log.trace("Looking for context of [{}] that satisfies a requested.", ctx);
				// first see if this context is directly in the requested list
				if (requestedContextList.contains(ctx) == true) {
					log.trace("Found parent context [{}] in requested list to use.", ctx);
					return ctx;
				}
				
				// must take the context they used and find parent of that context, we are
				// moving down the hierachy to find the lesser context that was requested and
				// satified by this higher context level
				Iterator<String> it = contextMap.keySet().iterator();
				while (it.hasNext() == true) {
					String key = it.next();
					Context context = contextMap.get(key);
					AllowedContexts ac = context.getAllowedContexts();
					// if no children, then go to the next one
					if (ac == null) continue;
					// we have children, see if we have a match
					for (Context child: ac.getContext()) {
						if (child.equals(ctx) == true) {
							if (requestedContextList.contains(context.getName()) == true) {
								log.trace("Found context [{}] in requested list to use. Returning parent [{}]", child.getName(), context.getName());
								return context.getName();
							}
						}
					}
				}
			}
		} catch (StackOverflowError e) {
			log.error("Exception while iterating over context graph.", e);
			return null;
		}
		
		log.trace("No match found, returning null.");
		return null;
	}

	/**
	 * Build a list of authentication contexts in a parent-child relationship. This will find all contexts
	 * that are descendents of the given context.
	 * 
	 * @param context The root context.
	 * @return
	 */
	private ArrayList<String> getGraphChildren(String context) {
		try {
			ArrayList<String> children = new ArrayList<String>();
			ContextGraph parent = graphMap.get(context);
			if (parent != null) {
				for (ContextGraph child: parent.allowed) {
					log.trace("  Adding context of [{}]", child.name);
					children.add(child.name);  // add this node
					ArrayList<String> grandchildren = getGraphChildren(child.name);
					if (grandchildren != null) children.addAll(grandchildren); // add any grand children it has
				}
				return children;
			}
			return null;
		} catch (StackOverflowError e) {
			log.error("Stack overflow while iterating over context graph.", e);
			return null;
		}
	}
	
	
	/**
	 * Get the list of values in the source list that are in the container list.
	 * @param source A list of context values.
	 * @param container A list of context values.
	 * @return The intersection of the lists.
	 */
	public ArrayList<String> getIntersection(List<String> source, List<String> container) {
		ArrayList<String> intersection = new ArrayList<String>();
		
		for (String ctx: source) {
			if (container.contains(ctx) == true) {
				intersection.add(ctx);
			}
		}
		
		return intersection;
	}
	
	/**
	 * Given the input parameters, validate that the user is allowed to use the current authentication
	 * context. If not, fail the request. In either case, set the potential context list in the principal.
	 * @param principal The current principal.
	 * @param ba The resolved list of allowed contexts of this principal.
	 * @param context The authentication context successfully used by the principal
	 * @return true if the used context is valid for this principal
	 */
	public boolean validatePotentialContext(MCBUsernamePrincipal principal, BaseAttribute ba, String contextUsed) {
		
		// clear any existing contexts
		principal.getPotentialContexts().clear();
		
		for (Object m1: ba.getValues().toArray()) {
			String ctx = (String) m1;
			log.debug("Adding potential context [{}] to list for principal [{}]", ctx, principal.getName());
    		principal.getPotentialContexts().add(ctx);
    	}
		
		// Save that this context was successfully used by the principal
		principal.getCurrentContexts().add(contextUsed);
		
		// look for the simple case that the just used context is in the potential list
		if (principal.getPotentialContexts().contains(contextUsed) == true) {
			log.debug("Found matching context value in potential list [{}] for principal [{}]", contextUsed, principal.getName());
			return true;
		}
		
		// the simple match did not match, so now we must check and see if the context used is a child
		// of one of the potential contexts
		for (String potential: principal.getPotentialContexts()) {
			// get the root node
			log.debug("Obtaining root node for [{}]", potential);
			ContextGraph cg = this.getGraphMap().get(potential);
			if (cg == null) continue;
			if (cg.matchContext(contextUsed) == true) {
				log.debug("Found context used as child of context [{}]", cg.name);
				return true;
			}
			
		}
		
		return false;
	}
	
	/**
	 * Given the input parameters, validate that the user is allowed to use the current authentication
	 * context. If not, fail the request.
	 * @param principal The current principal.
	 * @param context The authentication context successfully used by the principal
	 * @return true if the used context is valid for this principal
	 */
	public boolean validatePotentialContext(MCBUsernamePrincipal principal, String contextUsed) {
		
		// Save that this context was successfully used by the principal
		principal.getCurrentContexts().add(contextUsed);
		
		// look for the simple case that the just used context is in the potential list
		if (principal.getPotentialContexts().contains(contextUsed) == true) {
			log.debug("Found matching context value in potential list [{}] for principal [{}]", contextUsed, principal.getName());
			return true;
		}
		
		// the simple match did not match, so now we must check and see if the context used is a child
		// of one of the potential contexts
		for (String potential: principal.getPotentialContexts()) {
			// get the root node
			log.debug("Obtaining root node for [{}]", potential);
			ContextGraph cg = this.getGraphMap().get(potential);
			if (cg == null) continue;
			if (cg.matchContext(contextUsed) == true) {
				log.debug("Found context used as child of context [{}]", cg.name);
				return true;
			}
			
		}
		
		return false;
	}
	
	
	/**
	 * Get the Context object with this name from the graph map
	 * @param contextName
	 * @return
	 */
	public Context getContext(String contextName) {
		ContextGraph cg = graphMap.get(contextName);
		
		if (cg != null) {
			return contextMap.get(cg.name);
		}
		
		return null;
	}
	
	
	/**
	 * Recursive method to add our graph nodes
	 * @param context The current Context object.
	 * @return A new ContextGraph or null.
	 */
	protected ContextGraph addNode(Context context) {
		ContextGraph graph = null;
		
		graph = new ContextGraph(context.getName());
		if (context.getAllowedContexts() != null) {
			for (Context ctx: context.getAllowedContexts().getContext()) {
				log.info("  -- Adding child node of [{}]", ctx.getName());
				graph.allowed.add( addNode(ctx) );
			}
		}
		
		return graph;
	}

	public HashMap<String, MCBSubmodule> getSubmoduleMap() {
		return submoduleMap;
	}

	public void setSubmoduleMap(HashMap<String, MCBSubmodule> submoduleMap) {
		this.submoduleMap = submoduleMap;
	}

	public HashMap<String, Method> getMethodMap() {
		return methodMap;
	}

	public void setMethodMap(HashMap<String, Method> methodMap) {
		this.methodMap = methodMap;
	}

	public HashMap<String, Context> getContextMap() {
		return contextMap;
	}

	public void setContextMap(HashMap<String, Context> contextMap) {
		this.contextMap = contextMap;
	}

	public HashMap<String, ContextGraph> getGraphMap() {
		return graphMap;
	}

	public void setGraphMap(HashMap<String, ContextGraph> graphMap) {
		this.graphMap = graphMap;
	}

	public boolean isShowOnlyRequested() {
		return showOnlyRequested;
	}

	public void setShowOnlyRequested(boolean showOnlyRequested) {
		this.showOnlyRequested = showOnlyRequested;
	}

	public int getMaxFailures() {
		return maxFailures;
	}

	public void setMaxFailures(int maxFailures) {
		this.maxFailures = maxFailures;
	}

	public String getVelocityPropertiesFile() {
		return velocityPropertiesFile;
	}

	public void setVelocityPropertiesFile(String velocityPropertiesFile) {
		this.velocityPropertiesFile = velocityPropertiesFile;
	}

	public String getAttributeResolverID() {
		return attributeResolverID;
	}

	public void setAttributeResolverID(String attributeResolverID) {
		this.attributeResolverID = attributeResolverID;
	}

	public ArrayList<String> getDefaultContextList() {
		return defaultContextList;
	}

	public void setDefaultContextList(ArrayList<String> defaultContextList) {
		this.defaultContextList = defaultContextList;
	}

	public List<Method> getDefaultMethodList() {
		return defaultMethodList;
	}

	public boolean isPrincipalAuthnContextRequired() {
		return principalAuthnContextRequired;
	}

	public void setPrincipalAuthnContextRequired(
			boolean principalAuthnContextRequired) {
		this.principalAuthnContextRequired = principalAuthnContextRequired;
	}

	public AllowPrincipalSwitching getAllowPrincipalSwitching() {
		return allowPrincipalSwitching;
	}

	public void setAllowPrincipalSwitching(AllowPrincipalSwitching allowPrincipalSwitching) {
		this.allowPrincipalSwitching = allowPrincipalSwitching;
	}

	public boolean isShowSatisfiedContexts() {
		return showSatisfiedContexts;
	}

	public void setShowSatisfiedContexts(boolean showSatisfiedContexts) {
		this.showSatisfiedContexts = showSatisfiedContexts;
	}

}
