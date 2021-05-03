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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Configuration of the Attribute.
 * 
 * @author Vlastimil Elias <velias@redhat.com>
 *
 */
public class UPAttribute {

    protected String name;
    protected List<UPAttributeValidation> validations;
    protected Map<String, Object> annotations;
    protected UPAttributeRequirements requirements;
    protected UPAttributePermissions permissions;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name != null ? name.trim() : null;
    }

    public List<UPAttributeValidation> getValidations() {
        return validations;
    }

    public void setValidations(List<UPAttributeValidation> validations) {
        this.validations = validations;
    }

    public Map<String, Object> getAnnotations() {
        return annotations;
    }

    public void setAnnotations(Map<String, Object> annotations) {
        this.annotations = annotations;
    }

    public UPAttributeRequirements getRequirements() {
        return requirements;
    }

    public void setRequirements(UPAttributeRequirements requirements) {
        this.requirements = requirements;
    }

    public UPAttributePermissions getPermissions() {
        return permissions;
    }

    public void setPermissions(UPAttributePermissions permissions) {
        this.permissions = permissions;
    }

    @Override
    public String toString() {
        return "UPAttribute [name=" + name + ", permissions=" + permissions + ", requirements=" + requirements + ", validations=" + validations + ", annotations="
                + annotations + "]";
    }

    public void addValidation(UPAttributeValidation validation) {
        if (validations == null) {
            validations = new ArrayList<>();
        }

        validations.add(validation);
    }
}
