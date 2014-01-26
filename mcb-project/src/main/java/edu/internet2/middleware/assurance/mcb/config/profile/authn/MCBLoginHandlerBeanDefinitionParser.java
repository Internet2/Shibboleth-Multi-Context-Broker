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

import javax.xml.namespace.QName;

import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.idp.config.profile.ProfileHandlerNamespaceHandler;
import edu.internet2.middleware.shibboleth.idp.config.profile.authn.AbstractLoginHandlerBeanDefinitionParser;

/**
 * Spring bean definition parser for username/password authentication handlers.
 */
public class MCBLoginHandlerBeanDefinitionParser extends AbstractLoginHandlerBeanDefinitionParser {

    /** Schema type. */
    public static final QName SCHEMA_NAME = new QName(MCBLoginNamespaceHandler.NAMESPACE, "MultiContextBroker");

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(MCBLoginHandlerBeanDefinitionParser.class);

    /** {@inheritDoc} */
    protected Class getBeanClass(Element element) {
        return MCBLoginHandlerFactoryBean.class;
    }

    /** {@inheritDoc} */
    protected void doParse(Element config, BeanDefinitionBuilder builder) {
        super.doParse(config, builder);

        if (config.hasAttributeNS(null, "previousSession")) {
            builder.addPropertyValue("previousSession", XMLHelper.getAttributeValueAsBoolean(config
                    .getAttributeNodeNS(null, "previousSession")));
        } else {
            builder.addPropertyValue("previousSession", false);
        }

        if (config.hasAttributeNS(null, "depends-on")) {
            builder.addPropertyValue("dependsOn", DatatypeHelper.safeTrim(config.getAttributeNS(null,
                    "depends-on")));
        } else {
            builder.addPropertyValue("dependsOn", null);
        }

    }
}