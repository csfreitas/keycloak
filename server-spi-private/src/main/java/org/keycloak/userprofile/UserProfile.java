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
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.BinaryOperator;
import java.util.function.Consumer;

import org.keycloak.models.UserModel;

/**
 * Abstraction, which allows to update the user in various contexts (Required action of already existing user, or first identity provider
 * login when user doesn't yet exists in Keycloak DB)
 *
 * @author <a href="mailto:markus.till@bosch.io">Markus Till</a>
 */
public interface UserProfile {

    void validate(Map<String, ? extends Object> attributes) throws UserProfile.ProfileValidationException;

    void update(Map<String, ? extends Object> attributes, boolean removeAttributes, BiConsumer<String, UserModel>... attributeChangeListener) throws
            UserProfile.ProfileValidationException, UserProfile.ProfileUpdateException;

    default void update(Map<String, ? extends Object> attributes, BiConsumer<String, UserModel>... attributeChangeListener) throws
            UserProfile.ProfileValidationException, UserProfile.ProfileUpdateException {
        update(attributes, true, attributeChangeListener);
    }

    UserProfile.Attributes getAttributes();

    UserModel getUser();

    interface Attributes extends Map<String, List<String>> {

        String getFirstValue(String name);

        boolean isReadOnlyAttribute(String key);

        boolean validate(String key, List<String> value, Consumer<String> error);
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

        public boolean hasError(String... type) {
            return errors.containsKey(type);
        }

        public void addError(Error error) {
            errors.computeIfAbsent(error.getDescription(), (k) -> new ArrayList<>()).add(error);
        }
    }

    class ProfileUpdateException extends RuntimeException {

    }

    interface Error {
        String getAttribute();
        String getDescription();
    }

    /**
     * @author <a href="mailto:markus.till@bosch.io">Markus Till</a>
     */
    enum UserUpdateEvent {
        UpdateProfile,
        UserResource,
        Account,
        IdpReview,
        RegistrationProfile,
        RegistrationUserCreation
    }
}
