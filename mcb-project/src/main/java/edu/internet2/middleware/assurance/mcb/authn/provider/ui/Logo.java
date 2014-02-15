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
	
	/**
	 * Constructor -- takes a Logo of the language the page should be displayed in 
	 * @param l logo
	 */
	public Logo(org.opensaml.samlext.saml2mdui.Logo l){
		logo = l;
	}
	
	@Override
	public String toString(){
		Encoder enc = ESAPI.encoder();
		StringBuilder sb = new StringBuilder();
		sb.append("<img src=\"");
		sb.append(enc.encodeForHTMLAttribute(logo.getURL()));
		sb.append("\" height=\"");
		sb.append(logo.getHeight());
		sb.append("\" width=\"");
		sb.append(logo.getWidth());
		sb.append("\" alt=\"Service Logo\" />");
		
		return sb.toString();
	}
	
}
