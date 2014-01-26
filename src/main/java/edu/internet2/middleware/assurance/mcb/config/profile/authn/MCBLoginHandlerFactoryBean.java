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

package edu.internet2.middleware.assurance.mcb.config.profile.authn;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.assurance.mcb.authn.provider.MCBConfiguration;
import edu.internet2.middleware.assurance.mcb.authn.provider.MCBLoginHandler;

import edu.internet2.middleware.shibboleth.idp.authn.provider.UsernamePasswordLoginHandler;
import edu.internet2.middleware.shibboleth.idp.config.profile.authn.AbstractLoginHandlerFactoryBean;

/**
 * Factory bean for {@link UsernamePasswordLoginHandler}s.
 */
public class MCBLoginHandlerFactoryBean extends AbstractLoginHandlerFactoryBean {

    private final Logger log = LoggerFactory.getLogger(MCBLoginHandlerFactoryBean.class);

    private boolean previousSession = false;
	public void setPreviousSession(boolean previousSession) {
		this.previousSession = previousSession;
	}

	private String dependsOn = null;
	public void setDependsOn(String dependsOn) {
		this.dependsOn = dependsOn;
	}
	
	
    /** {@inheritDoc} */
    protected Object createInstance() throws Exception {
        MCBLoginHandler handler = new MCBLoginHandler();
        handler.setPreviousSession(previousSession);

        try {
        	log.debug("Attempting to load bean [{}]", dependsOn);
        	Object o = getBeanFactory().getBean(dependsOn);
        	
        	if (o instanceof MCBConfiguration) {
        		handler.setMcbConfiguration((MCBConfiguration)o);
        		log.debug("MCBConfiguration bean = [{}]", o);
        	}
        	
        } catch (Exception e) {
        	log.error("", e);
        }
        populateHandler(handler);

        return handler;
    }

    /** {@inheritDoc} */
    public Class getObjectType() {
        return MCBLoginHandler.class;
    }
}