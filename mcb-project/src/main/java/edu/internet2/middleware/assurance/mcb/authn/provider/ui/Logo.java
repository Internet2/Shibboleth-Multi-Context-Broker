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

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;

/**
 * This class handles the UI logo.
 * @author David Langenberg <davel@uchicago.edu>
 */
public class Logo {
	
	private org.opensaml.samlext.saml2mdui.Logo logo;
	
	private Encoder enc;
	
	/**
	 * Constructor -- takes a Logo of the language the page should be displayed in 
	 * @param l logo
	 */
	public Logo(org.opensaml.samlext.saml2mdui.Logo l){
		logo = l;
		enc = ESAPI.encoder();
	}
	
	/**
	 * Gets the URL of the logo.  Passes it through the OWASP canonicalizer & encoder
	 * first to ensure it's safe for inclusion in a src= attribute
	 * @return encoded URL
	 */
	public String getURL(){
		return enc.encodeForHTMLAttribute(enc.canonicalize(logo.getURL()));
	}
	
	/**
	 * Gets the width of the image from metadata
	 * @return encoded width value
	 */
	public String getWidth(){
		return enc.encodeForHTMLAttribute(logo.getWidth().toString());
	}
	
	/**
	 * Gets the height of the image from metadata
	 * @return encoded height value
	 */
	public String getHeight(){
		return enc.encodeForHTMLAttribute(logo.getHeight().toString());
	}
	
	@Override
	public String toString(){
		StringBuilder sb = new StringBuilder();
		sb.append("<img src=\"");
		sb.append(getURL());
		sb.append("\" height=\"");
		sb.append(logo.getHeight());
		sb.append("\" width=\"");
		sb.append(logo.getWidth());
		sb.append("\" alt=\"Service Logo\" />");
		
		return sb.toString();
	}
	
}
