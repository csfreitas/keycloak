/*
 *
 *  * Copyright 2021  Red Hat, Inc. and/or its affiliates
 *  * and other contributors as indicated by the @author tags.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  * http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package org.keycloak.userprofile.validation;

import java.util.List;
import java.util.function.BiFunction;

import org.keycloak.userprofile.UserProfile;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class AttributeValidator {

    private final String attributeName;
    final String message;
    final Validator validator;

    public AttributeValidator(String attributeName, String message, Validator validator) {
        this.attributeName = attributeName;
        this.message = message;
        this.validator = validator;
    }

    public String getAttributeName() {
        return attributeName;
    }

    public Validator getValidator() {
        return validator;
    }

    public String getMessage() {
        return message;
    }
}
