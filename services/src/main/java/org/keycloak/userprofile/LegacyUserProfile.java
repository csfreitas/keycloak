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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.messages.Messages;
import org.keycloak.userprofile.validation.AttributeValidator;
import org.keycloak.userprofile.validation.StaticValidators;
import org.keycloak.userprofile.validation.Validator;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class LegacyUserProfile implements UserProfile {

    private final DefaultContextKey context;
    private final UserModel user;
    private final DefaultAttributes attributes;
    private final KeycloakSession session;
    private final Pattern adminReadOnlyAttributes;
    private final Pattern readOnlyAttributes;
    private boolean validated;

    public LegacyUserProfile(DefaultContextKey context, DefaultAttributes attributes, UserModel user,
            KeycloakSession session,
            Pattern adminReadOnlyAttributes, Pattern readOnlyAttributes) {
        this.context = context;
        this.user = user;
        this.attributes = attributes;
        this.session = session;
        this.adminReadOnlyAttributes = adminReadOnlyAttributes;
        this.readOnlyAttributes = readOnlyAttributes;
    }

    @Override
    public void validate() throws ProfileValidationException {
        ProfileValidationException validationException = new ProfileValidationException();
        List<AttributeValidator> validators = new ArrayList<>();
        RealmModel realm = session.getContext().getRealm();

        switch (context) {
            case USER_RESOURCE:
                validators.addAll(addReadOnlyAttributeValidators(adminReadOnlyAttributes));
                break;
            case IDP_REVIEW:
                validators.addAll(addBasicValidators(!realm.isRegistrationEmailAsUsername()));
                validators.addAll(addReadOnlyAttributeValidators(readOnlyAttributes));
                break;
            case ACCOUNT:
            case REGISTRATION_PROFILE:
            case UPDATE_PROFILE:
                validators.addAll(addBasicValidators(!realm.isRegistrationEmailAsUsername() && realm.isEditUsernameAllowed()));
                validators.addAll(addReadOnlyAttributeValidators(readOnlyAttributes));
                validators.addAll(addSessionValidators());
                break;
            case REGISTRATION_USER_CREATION:
                addUserCreationValidators();
                validators.addAll(addReadOnlyAttributeValidators(readOnlyAttributes));
                break;
        }

        for (AttributeValidator validator : validators) {
            attributes.addValidator(validator);
        }

        for (Map.Entry<String, List<String>> attribute : attributes.entrySet()) {
            String key = attribute.getKey();
            Object value = attribute.getValue();

            if (value instanceof String) {
                value = Collections.singleton((String) value);
            }

            this.attributes.validate(attribute, new Consumer<String>() {
                @Override
                public void accept(String error) {
                    validationException.addError(new Error() {
                        @Override
                        public String getAttribute() {
                            return key;
                        }

                        @Override
                        public String getMessage() {
                            return error;
                        }
                    });
                }
            });
        }

        if (!validationException.getErrors().isEmpty()) {
            throw validationException;
        }

        validated = true;
    }

    @Override
    public void update(boolean removeAttributes, BiConsumer<String, UserModel>... attributeChangeListener)
            throws ProfileValidationException, ProfileUpdateException {
        if (!validated) {
            validate();
        }

        if (user == null) {
            return;
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

    private AttributeValidator addAttributeValidator(String name, String message, Validator validator) {
        return new AttributeValidator(name, message, validator);
    }

    private static List<String> AttributeToLower(List<String> attr) {
        if (attr.size() == 1 && attr.get(0) != null)
            return Collections.singletonList(KeycloakModelUtils.toLowerCaseSafe(attr.get(0)));
        return attr;
    }

    private List<AttributeValidator> addUserCreationValidators() {
        RealmModel realm = this.session.getContext().getRealm();

        if (realm.isRegistrationEmailAsUsername()) {
            return Arrays.asList(addAttributeValidator(UserModel.EMAIL, Messages.INVALID_EMAIL, StaticValidators.isEmailValid()),
                    addAttributeValidator(UserModel.EMAIL, Messages.MISSING_EMAIL, StaticValidators.isBlank()),
                    addAttributeValidator(UserModel.EMAIL, Messages.EMAIL_EXISTS, StaticValidators.doesEmailExist(session)));
        }

        return Arrays.asList(addAttributeValidator(UserModel.USERNAME, Messages.MISSING_USERNAME, StaticValidators.isBlank()),
                addAttributeValidator(UserModel.USERNAME, Messages.USERNAME_EXISTS,
                        new Validator() {
                            @Override
                            public Boolean validate(Map.Entry<String, List<String>> attribute, UserModel user) {
                                List<String> values = attribute.getValue();

                                if (values.isEmpty()) {
                                    return true;
                                }

                                String value = values.get(0);

                                UserModel existing = session.users().getUserByUsername(realm, value);
                                return existing == null || existing.getId().equals(user.getId());
                            }
                        }));
    }

    private List<AttributeValidator> addBasicValidators(boolean userNameExistsCondition) {
        return Arrays.asList(addAttributeValidator(UserModel.USERNAME, Messages.MISSING_USERNAME, StaticValidators.checkUsernameExists(userNameExistsCondition)),
                addAttributeValidator(UserModel.FIRST_NAME, Messages.MISSING_FIRST_NAME, StaticValidators.isBlank()),
                addAttributeValidator(UserModel.LAST_NAME, Messages.MISSING_LAST_NAME, StaticValidators.isBlank()),
                addAttributeValidator(UserModel.EMAIL, Messages.MISSING_EMAIL, StaticValidators.isBlank()),
                addAttributeValidator(UserModel.EMAIL, Messages.INVALID_EMAIL, StaticValidators.isEmailValid()));
    }

    private List<AttributeValidator> addSessionValidators() {
        RealmModel realm = this.session.getContext().getRealm();
        return Arrays.asList(addAttributeValidator(UserModel.USERNAME, Messages.USERNAME_EXISTS, StaticValidators.userNameExists(session)),
                addAttributeValidator(UserModel.USERNAME, Messages.READ_ONLY_USERNAME, StaticValidators.isUserMutable(realm)),
                addAttributeValidator(UserModel.EMAIL, Messages.EMAIL_EXISTS, StaticValidators.isEmailDuplicated(session)),
                addAttributeValidator(UserModel.EMAIL, Messages.USERNAME_EXISTS, StaticValidators.doesEmailExistAsUsername(session)));
    }

    private List<AttributeValidator> addReadOnlyAttributeValidators(Pattern configuredReadOnlyAttrs) {
        return Arrays.asList(addValidatorsForReadOnlyAttributes(configuredReadOnlyAttrs));
    }


    private AttributeValidator addValidatorsForReadOnlyAttributes(Pattern configuredReadOnlyAttrsPattern) {
        return addAttributeValidator("*", Messages.UPDATE_READ_ONLY_ATTRIBUTES_REJECTED, StaticValidators.isReadOnlyAttributeUnchanged(configuredReadOnlyAttrsPattern));
    }
}
