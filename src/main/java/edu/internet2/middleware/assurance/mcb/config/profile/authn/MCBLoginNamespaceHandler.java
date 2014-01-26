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

import edu.internet2.middleware.shibboleth.common.config.BaseSpringNamespaceHandler;

/**
 * Spring namespace handler for the Shibboleth static data connector namespace.
 */
public class MCBLoginNamespaceHandler extends BaseSpringNamespaceHandler {

    /** Namespace for this handler. */
    public static final String NAMESPACE = "edu:internet2:middleware:assurance:mcb";

    /** {@inheritDoc} */
    public void init() {
        registerBeanDefinitionParser(MCBLoginHandlerBeanDefinitionParser.SCHEMA_NAME,
                new MCBLoginHandlerBeanDefinitionParser());
    }
}