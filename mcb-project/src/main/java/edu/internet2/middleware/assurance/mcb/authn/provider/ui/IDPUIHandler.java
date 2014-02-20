/*
 * Copyright 2014 The University of Chicago.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package edu.internet2.middleware.assurance.mcb.authn.provider.ui;

import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfigurationManager;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import edu.internet2.middleware.shibboleth.idp.ui.ServiceTagSupport;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.samlext.saml2mdui.Description;
import org.opensaml.samlext.saml2mdui.DisplayName;
import org.opensaml.samlext.saml2mdui.InformationURL;
import org.opensaml.samlext.saml2mdui.Logo;
import org.opensaml.samlext.saml2mdui.PrivacyStatementURL;
import org.opensaml.samlext.saml2mdui.UIInfo;
import org.opensaml.xml.XMLObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class to handle getting IDPUI information so that it can be injected into
 * Velocity templates
 *
 * Contains some code taken from
 * @seeAlso{edu.internet2.middleware.shibboleth.idp.ui.ServiceTagSupport}
 *
 * @author David Langenberg <davel@uchicago.edu>
 */
public class IDPUIHandler {

    private final Logger log = LoggerFactory.getLogger(IDPUIHandler.class);
    private UIInfo info;
    private String lang;
    private HttpServletRequest request;
    private ServletContext application;

    /**
     * Constructor
     *
     * @param req the servlet request
     */
    public IDPUIHandler(HttpServletRequest req, ServletContext ctx) {
        super();
        request = req;
        application = ctx;
        lang = request.getLocale().getLanguage();
        log.debug("target language is " + lang);
        info = getSPUIInfo();
    }

    /**
     * Traverse the SP's EntityDescriptor and pick out the UIInfo.
     *
     * @return the first UIInfo for the SP.
     */
    private UIInfo getSPUIInfo() {
        EntityDescriptor spEntity = getSPEntityDescriptor();
        Extensions exts;

        if (null == spEntity) {
            log.debug("spEntity is null");
            //
            // all done
            //
            return null;
        }

        for (RoleDescriptor role : spEntity.getRoleDescriptors(SPSSODescriptor.DEFAULT_ELEMENT_NAME)) {
            exts = role.getExtensions();
            if (exts != null) {
                for (XMLObject object : exts.getOrderedChildren()) {
                    if (object instanceof UIInfo) {
                        return (UIInfo) object;
                    }
                }
            }
        }
        log.debug("no UI info in EntityDescriptor {}", spEntity.getEntityID());
        return null;
    }

    /**
     * Overrides ServiceTagSupport's version as we are being passed some of the
     * stuff that the super class expects to have already
     *
     * @return the EntittyDescriptor
     */
    protected EntityDescriptor getSPEntityDescriptor() {
        LoginContext loginContext;
        RelyingPartyConfigurationManager rpConfigMngr;
        EntityDescriptor spEntity;

        //
        // grab the login context and the RP config mgr.
        //
        loginContext
                = HttpServletHelper.getLoginContext(HttpServletHelper.getStorageService(application), application,
                        request);
        rpConfigMngr = HttpServletHelper.getRelyingPartyConfigurationManager(application);
        if (loginContext == null || rpConfigMngr == null) {
            return null;
        }
        spEntity = HttpServletHelper.getRelyingPartyMetadata(loginContext.getRelyingPartyId(), rpConfigMngr);
        log.debug("SPEntity is {}", spEntity.getEntityID());
        return spEntity;

    }

    /**
     * Get the EntityID of the SP
     *
     * @return entityID of the SP or null
     */
    public String getEntityID() {
        EntityDescriptor entity = getSPEntityDescriptor();

        if (getSPEntityDescriptor() != null) {
            return entity.getEntityID();
        }

        return null;
    }

    /**
     * Service description
     *
     * @return description or null
     */
    public String getServiceDescription() {
        if (info != null) {
            for (Description desc : info.getDescriptions()) {
                log.debug("Found description in UIInfo, language={}", desc.getXMLLang());
                if (desc.getXMLLang().equals(lang)) {
                    log.debug("returning description from UIInfo {}", desc.getName().getLocalString());
                    return desc.getName().getLocalString();
                }
            }
        }
        return null;
    }

    /**
     * Get the service Name
     *
     * @return service name or null
     */
    public String getServiceName() {
        if (info != null) {
            for (DisplayName name : info.getDisplayNames()) {
                log.debug("Found service name in UIInfo, language={}", name.getXMLLang());

                if (name.getXMLLang().equals(lang)) {
                    log.debug("returning service name from UIInfo {}", name.getName().getLocalString());
                    return name.getName().getLocalString();
                }
            }
        }

        return null;
    }

    /**
     * Get the URL of the service logo
     *
     * @return Logo URL or null
     */
    public Logo getServiceLogo() {
        if (info != null) {
            for (Logo logo : info.getLogos()) {
                log.debug("Found Logo in UIInfo, language={}", logo.getXMLLang());

                if (logo.getXMLLang().equals(lang)) {
                    log.debug("returning logo from UIInfo {}", logo.getURL());
                    return logo;
                }
            }
        }
        return null;
    }

    /**
     * Get the information URL
     *
     * @return information URL as a string or null
     */
    public String getInformationURL() {
        if (info != null) {
            for (InformationURL url : info.getInformationURLs()) {
                log.debug("Found information URL in UIInfo, language={}", url.getXMLLang());

                if (url.getXMLLang().equals(lang)) {
                    log.debug("returning information URL {}", url.getURI().getLocalString());
                    return url.getURI().getLocalString();
                }
            }
        }
        return null;
    }

    /**
     * Get the privacy policy URL
     *
     * @return privacy policy URL or null
     */
    public String getPrivacyURL() {
        if (info != null) {
            for (PrivacyStatementURL url : info.getPrivacyStatementURLs()) {
                log.debug("Found privacy URL in UIInfo, language={}", url.getXMLLang());

                if (url.getXMLLang().equals(lang)) {
                    log.debug("returning privacy URL, {}", url.getURI().getLocalString());
                    return url.getURI().getLocalString();
                }
            }
        }

        return null;
    }
}
