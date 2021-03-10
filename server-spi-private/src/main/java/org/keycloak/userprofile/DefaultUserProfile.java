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

package org.keycloak.userprofile;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;

import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class DefaultUserProfile implements UserProfile {

    private final ContextKey context;
    private final UserModel user;
    private final DefaultAttributes attributes;
    private boolean validated;

    public DefaultUserProfile(ContextKey context, DefaultAttributes attributes, UserModel user) {
        this.context = context;
        this.user = user;
        this.attributes = attributes;
    }

    @Override
    public void validate() throws ProfileValidationException {
        ProfileValidationException validationException = new ProfileValidationException();

        for (Map.Entry<String, List<String>> attribute : attributes.entrySet()) {
            this.attributes.validate(attribute, error -> validationException.addError(new Error() {
                @Override
                public String getAttribute() {
                    return attribute.getKey();
                }

                @Override
                public String getMessage() {
                    return error;
                }
            }));
        }

        if (!validationException.getErrors().isEmpty()) {
            throw validationException;
        }

        validated = true;
    }

    @Override
    public void update(boolean removeAttributes, BiConsumer<String, UserModel>... attributeChangeListener)
            throws ProfileValidationException, ProfileUpdateException {
        if (user == null) {
            return;
        }

        if (!validated) {
            validate();
        }


        for (Map.Entry<String, List<String>> attr : attributes.entrySet()) {
            List<String> currentValue = user.getAttributeStream(attr.getKey()).collect(Collectors.toList());
            //In case of username we need to provide lower case values
            List<String> updatedValue = attr.getKey().equals(UserModel.USERNAME) ? AttributeToLower(attr.getValue()) : attr.getValue();
            if (currentValue.size() != updatedValue.size() || !currentValue.containsAll(updatedValue)) {
                user.setAttribute(attr.getKey(), updatedValue);
                for (BiConsumer<String, UserModel> listener : attributeChangeListener) {
                    listener.accept(attr.getKey(), user);
                }
            }
        }

        if (removeAttributes) {
            Set<String> attrsToRemove = new HashSet<>(user.getAttributes().keySet());
            attrsToRemove.removeAll(attributes.keySet());

            for (String attr : attrsToRemove) {
                if (this.attributes.isReadOnlyAttribute(attr)) {
                    continue;
                }
                user.removeAttribute(attr);
            }

        }
    }

    @Override
    public Attributes getAttributes() {
        return attributes;
    }

    private static List<String> AttributeToLower(List<String> attr) {
        if (attr.size() == 1 && attr.get(0) != null)
            return Collections.singletonList(KeycloakModelUtils.toLowerCaseSafe(attr.get(0)));
        return attr;
    }
}
