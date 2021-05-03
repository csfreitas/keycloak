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

import java.util.Map;

/**
 * Configuration of the one attribute validation.
 * 
 * @author Vlastimil Elias <velias@redhat.com>
 *
 */
public class UPAttributeValidation {

    protected String validator;
    protected Map<String, Object> config;

    public UPAttributeValidation() {
        this(null, null);
    }

    public UPAttributeValidation(String validator, Map<String, Object> config) {
        this.validator = validator;
        this.config = config;
    }

    public String getValidator() {
        return validator;
    }

    public void setValidator(String validator) {
        this.validator = validator;
    }

    public Map<String, Object> getConfig() {
        return config;
    }

    public void setConfiguration(Map<String, Object> config) {
        this.config = config;
    }

    @Override
    public String toString() {
        return "UPAttributeValidation [validator=" + validator + ", configuration=" + config + "]";
    }

}
