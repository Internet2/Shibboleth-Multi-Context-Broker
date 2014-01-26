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
/*
 * Licensed to the University Corporation for Advanced Internet Development, 
 * Inc. (UCAID) under one or more contributor license agreements.  See the 
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache 
 * License, Version 2.0 (the "License"); you may not use this file except in 
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.assurance.mcb.authn.provider;

import java.io.Serializable;

/** Represents a username and password entered used to authenticate a subject. */
public class UsernamePasswordCredential implements Serializable{

    /** Serial version UID. */
    private static final long serialVersionUID = -5262041398037656037L;

    /** Username of a subject. */
    private String username;

    /** Password of a subject. */
    private String password;

    /**
     * Constructor.
     * 
     * @param name username of the subject
     * @param pass password of the subject
     */
    public UsernamePasswordCredential(String name, String pass) {
        username = name;
        password = pass;
    }

    /**
     * Gets the username of the subject.
     * 
     * @return username of the subject
     */
    public String getUsername() {
        return username;
    }

    /**
     * Gets the password of the subject.
     * 
     * @return password of the subject
     */
    public String getPassword() {
        return password;
    }
}