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

import java.io.Serializable;
import java.security.Principal;
import java.util.ArrayList;

import org.opensaml.xml.util.DatatypeHelper;

/**
 * The Principal type used by the MCB.
 * 
 * @author Paul Hethmon
 *
 */
public class MCBUsernamePrincipal implements Principal, Serializable {

	private static final long serialVersionUID = 639746289834646392L;

	private String failedLogin = null;
	private int failedCount = 0;
	private String principalName = null;
	
	private ArrayList<String> potentialContexts = null;
	private ArrayList<String> currentContexts = null;
	
	
	public MCBUsernamePrincipal(String principalName) {
		this.principalName = principalName;
		potentialContexts = new ArrayList<String>();
		currentContexts = new ArrayList<String>();
	}

	public void setName(String principalName) {
		this.principalName = principalName;
	}

	public String getFailedLogin() {
		return failedLogin;
	}

	public void setFailedLogin(String failedLogin) {
		this.failedLogin = failedLogin;
	}

	public int getFailedCount() {
		return failedCount;
	}

	public void setFailedCount(int failedCount) {
		this.failedCount = failedCount;
	}

	public String getName() {
		return principalName;
	}

    /** {@inheritDoc} */
    public String toString() {
        return "{MCBUsernamePrincipal}" + getName();
    }

    /**
     * Return a full set of information suitable for printing.
     * 
     * @param all If true return everything. If false, use normal toString method
     * @return
     */
    public String toString(boolean all) {
    	// use regular one if false
    	if (all == false) return toString();
    	
    	StringBuilder sb = new StringBuilder();
    	String endofline = System.getProperty("line.separator");
    	sb.append("{MCBUsernamePrincipal}" + getName() + endofline);
    	sb.append("  failedCount = [" + failedCount + "]" + endofline);
    	sb.append("  failedLogin = [" + failedLogin + "]" + endofline);
    	for (String ctx: currentContexts) {
    		sb.append("  CurrentContext = [" + ctx + "]" + endofline);
    	}
    	for (String ctx: potentialContexts) {
    		sb.append("  PotentialContext = [" + ctx + "]" + endofline);
    	}
    	
    	return sb.toString();
    }
    
    /** {@inheritDoc} */
    public int hashCode() {
        return principalName.hashCode();
    }

    /** {@inheritDoc} */
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }

        if (obj instanceof Principal) {
            return DatatypeHelper.safeEquals(getName(), ((Principal) obj).getName());
        }

        return false;
    }

    /**
     * The list of potential contexts this principal is allowed to use.
     * @return
     */
	public ArrayList<String> getPotentialContexts() {
		return potentialContexts;
	}

    /**
     * The list of potential contexts this principal is allowed to use.
     * @return
     */
	public void setPotentialContexts(ArrayList<String> potentialContexts) {
		this.potentialContexts = potentialContexts;
	}

    /**
     * The list of current contexts this principal has used.
     * @return
     */
	public ArrayList<String> getCurrentContexts() {
		return currentContexts;
	}

    /**
     * The list of current contexts this principal has used.
     * @return
     */
	public void setCurrentContexts(ArrayList<String> currentContexts) {
		this.currentContexts = currentContexts;
	}

}
