/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.testsuite.user.profile.config;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;

/**
 * Config of the rules when attribute is required.
 * 
 * @author Vlastimil Elias <velias@redhat.com>
 *
 */
public class UPAttributeRequirements {

    protected Boolean always;
    protected List<String> roles;
    protected List<String> scopes;

    public boolean isAlways() {
        return always != null && always;
    }

    public void setAlways(boolean always) {
        this.always = always;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public void setScopes(List<String> scopes) {
        this.scopes = scopes;
    }

    /**
     * Check if this requirement config means that the attribute is never required (is always optional).
     * 
     * @return true if this config means that the attribute is never required
     */
    @JsonIgnore
    public boolean isNeverRequired() {
        return !isAlways() && (roles == null || roles.isEmpty()) && (scopes == null || scopes.isEmpty());
    }

    @Override
    public String toString() {
        return "UPAttributeRequirements [always=" + always + ", roles=" + roles + ", scopes=" + scopes + "]";
    }

}
