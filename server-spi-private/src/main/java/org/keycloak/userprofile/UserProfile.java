/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.userprofile;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

import org.keycloak.models.UserModel;

/**
 * Abstraction, which allows to update the user in various contexts (Required action of already existing user, or first identity provider
 * login when user doesn't yet exists in Keycloak DB)
 *
 * @author <a href="mailto:markus.till@bosch.io">Markus Till</a>
 */
public interface UserProfile {

    void validate() throws UserProfile.ProfileValidationException;

    void update(boolean removeAttributes, BiConsumer<String, UserModel>... attributeChangeListener) throws
            UserProfile.ProfileValidationException, UserProfile.ProfileUpdateException;

    default void update(BiConsumer<String, UserModel>... attributeChangeListener) throws
            UserProfile.ProfileValidationException, UserProfile.ProfileUpdateException {
        update(true, attributeChangeListener);
    }

    UserProfile.Attributes getAttributes();

    interface Attributes extends Map<String, List<String>> {

        String getFirstValue(String name);

        /**
         * Checks whether an attribute is read-only.
         *
         * @param key
         * @return
         */
        boolean isReadOnlyAttribute(String key);

        boolean validate(Map.Entry<String, List<String>> attribute, Consumer<String> error);
    }

    class ProfileValidationException extends RuntimeException {

        private Map<String, List<Error>> errors = new HashMap<>();

        public List<Error> getErrors() {
            return errors.values().stream().reduce(new ArrayList<>(),
                    (errors, errors2) -> {
                        errors.addAll(errors2);
                        return errors;
                    }, (errors, errors2) -> errors);
        }

        public boolean hasError(String... types) {
            for (String type : types) {
                if (errors.containsKey(type)) {
                    return true;
                }
            }
            return false;
        }

        public void addError(Error error) {
            errors.computeIfAbsent(error.getMessage(), (k) -> new ArrayList<>()).add(error);
        }
    }

    class ProfileUpdateException extends RuntimeException {

    }

    interface Error {
        String getAttribute();

        //TODO: support parameters to messsages for formatting purposes. Message key and parameters.
        String getMessage();
    }

    /**
     * @author <a href="mailto:markus.till@bosch.io">Markus Till</a>
     */
    enum DefaultContextKey implements ContextKey {
        UPDATE_PROFILE,
        USER_RESOURCE,
        ACCOUNT,
        IDP_REVIEW,
        REGISTRATION_PROFILE,
        REGISTRATION_USER_CREATION
    }

    interface ContextKey {
        String name();
    }

    default ContextKey key(String name) {
        return new ContextKey() {
            @Override
            public String name() {
                return name;
            }
        };
    }
}
