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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.common.SAMLObject;
import org.opensaml.ws.transport.InTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolver;
import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.ProfileConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationException;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;

/**
 * Resolve our attribute to determine the list of authentication context values a user is allowed. All
 * of this code based on Shibboleth code, some public contributions, and various examples.
 * 
 * @author Paul Hethmon
 *
 */
public class MCBAttributeResolver {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(MCBAttributeResolver.class);

    /** Names of user attributes to resolve and manage. */
    private List<String> attributeNames;
    
    @SuppressWarnings("rawtypes")
	private Map<String, BaseAttribute> attributes;

    public void resolve(MCBLoginServlet servlet, HttpServletRequest request, HttpServletResponse response,
            String principalName, String relyingPartyId) throws AuthenticationException {

        // We have to know the username.
        if (principalName == null) {
            log.debug("Username not set, returning");
            return;
        }

        log.debug("Performing attribute resolution for {}", principalName);

        @SuppressWarnings("rawtypes")
		AttributeResolver resolver = HttpServletHelper.getAttributeResolver(servlet.getServletContext());
        if (resolver != null) {
            try {
                attributes = resolver.resolveAttributes(createRequestContext(
                        servlet.getServletContext(), request, principalName, relyingPartyId));
                //Map<String, String> attributeMap = new HashMap<String, String>();
                String endofline = System.getProperty("line.separator");
                for (String key: attributes.keySet()) {
                	log.debug("Attribute key = [{}]", key);
                	log.debug("{}", attributes.get(key));
                	BaseAttribute ba = attributes.get(key);
                	StringBuilder sb = new StringBuilder();
                	sb.append(endofline);
                	sb.append("ID = " + ba.getId() + endofline);
                	for (Object m1: ba.getDisplayNames().keySet()) {
                		sb.append("DisplayName = " + ba.getDisplayNames().get(m1) + endofline);
                	}
                	for (Object m1: ba.getDisplayDescriptions().keySet()) {
                		sb.append("DisplayDescription = " + ba.getDisplayDescriptions().get(m1) + endofline);
                	}
                	for (Object m1: ba.getValues().toArray()) {
                		sb.append("Value = " + m1 + endofline);
                	}
                	log.debug(sb.toString());
                }                
            } catch (AttributeResolutionException e) {
                log.error("Failed to resolve attributes for {}: {}", principalName, e.getMessage());
            }
        } else {
            log.warn("No AttributeResolver instance available");
        }

        return;
    }

    /**
     * Convert the list of attribute values to a list of String objects.
     * @param ba The attribute
     * @return A list which may have no members.
     */
    public ArrayList<String> getValueList(BaseAttribute ba) {
    	ArrayList<String> valueList = new ArrayList<String>();
    	if (ba == null) return valueList;
    	
    	for (Object m1: ba.getValues().toArray()) {
    		if (m1 instanceof String) {
    			String tmp = (String) m1;
    			// do not store empty strings
    			if ((tmp != null) && (tmp.length() > 0)) {
    				valueList.add(tmp);
    			}
    		}
    	}
    	return valueList;
    }
    
    
    /**
     * Gets the attribute names to resolve.
     * @return the attribute names to resolve
     */
    public List<String> getAttributeNames() {
        return attributeNames;
    }

    /**
     * Sets the attribute names to resolve
     * @param attributeNames the attribute names to resolve
     */
    public void setAttributeNames(List<String> attributeNames) {
        this.attributeNames = attributeNames;
    }
    
    private BaseSAMLProfileRequestContext<?, ?, ?, ?> createRequestContext(ServletContext context,
            HttpServletRequest request, String principalName, String relyingPartyId) {
    	
        BaseSAMLProfileRequestContext<?, ?, ?, ?> requestContext = new BaseSAMLProfileRequestContext<SAMLObject, SAMLObject, SAMLObject, ProfileConfiguration>();
        RelyingPartyConfiguration relyingPartyConfiguration = HttpServletHelper.getRelyingPartyConfigurationManager(context).getRelyingPartyConfiguration(relyingPartyId);
        String idpId = relyingPartyConfiguration.getProviderId();

        requestContext.setRelyingPartyConfiguration(relyingPartyConfiguration);
        requestContext.setInboundMessageIssuer(relyingPartyId);
        // TODO -- create the InTransport
        requestContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));
        requestContext.setOutboundMessageIssuer(idpId);
        requestContext.setPrincipalName(principalName);
        requestContext.setLocalEntityId(idpId);
        requestContext.setPeerEntityId(relyingPartyId);
        requestContext.setRequestedAttributes(attributeNames);

        return requestContext;
    }

	public Map<String, BaseAttribute> getAttributes() {
		return attributes;
	}

	
}
