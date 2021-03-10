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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.messages.Messages;
import org.keycloak.userprofile.validation.StaticValidators;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class LegacyUserProfile implements UserProfile {

    private final String context;
    private final UserModel user;
    private final DefaultAttributes attributes;
    private final KeycloakSession session;
    private final Pattern adminReadOnlyAttributes;
    private final Pattern readOnlyAttributes;

    public LegacyUserProfile(String context, UserModel user, KeycloakSession session,
            Pattern adminReadOnlyAttributes, Pattern readOnlyAttributes) {
        this.context = context;
        this.user = user;
        this.attributes = new DefaultAttributes(user, this, adminReadOnlyAttributes, readOnlyAttributes);
        this.session = session;
        this.adminReadOnlyAttributes = adminReadOnlyAttributes;
        this.readOnlyAttributes = readOnlyAttributes;
    }

    @Override
    public void validate(Map<String, ?> attributes) throws ProfileValidationException {
        ProfileValidationException validationException = new ProfileValidationException();

        if (attributes != null) {
            Map<String, List<String>> newAttributes = (Map<String, List<String>>) attributes;
            RealmModel realm = session.getContext().getRealm();

            switch (DefaultContextKey.valueOf(context)) {
                case USER_RESOURCE:
                    addReadOnlyAttributeValidators(adminReadOnlyAttributes, newAttributes);
                    break;
                case IDP_REVIEW:
                    addBasicValidators(!realm.isRegistrationEmailAsUsername());
                    addReadOnlyAttributeValidators(readOnlyAttributes, newAttributes);
                    break;
                case ACCOUNT:
                case REGISTRATION_PROFILE:
                case UPDATE_PROFILE:
                    addBasicValidators(!realm.isRegistrationEmailAsUsername() && realm.isEditUsernameAllowed());
                    addReadOnlyAttributeValidators(readOnlyAttributes, newAttributes);
                    addSessionValidators();
                    break;
                case REGISTRATION_USER_CREATION:
                    addUserCreationValidators();
                    addReadOnlyAttributeValidators(readOnlyAttributes, newAttributes);
                    break;
            }

            for (Map.Entry<String, ?> attribute : attributes.entrySet()) {
                String key = attribute.getKey();
                Object value = attribute.getValue();

                if (value instanceof String) {
                    value = Collections.singleton((String) value);
                }

                this.attributes.validate(key, (List<String>) value, new Consumer<String>() {
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
        }

        if (!validationException.getErrors().isEmpty()) {
            throw validationException;
        }
    }

    @Override
    public void update(Map<String, ?> attributes, boolean removeAttributes, BiConsumer<String, UserModel>... attributeChangeListener)
            throws ProfileValidationException, ProfileUpdateException {
        DefaultContextKey context = DefaultContextKey.valueOf(this.context);
        Map<String, List<String>> newAttributes = Collections.emptyMap();

        if (attributes != null && !attributes.isEmpty()) {
            newAttributes = new HashMap<>();
            for (Map.Entry<String, ?> entry : attributes.entrySet()) {
                Object value = entry.getValue();

                if (value instanceof String) {
                    newAttributes.put(entry.getKey(), Collections.singletonList((String) value));
                } else {
                    newAttributes.put(entry.getKey(), (List<String>) value);
                }
            }
        }

        if (user == null || attributes == null || attributes.size() == 0) {
            return;
        }

        filterAttributes(context, session.getContext().getRealm(), newAttributes);
        updateAttributes(newAttributes, removeAttributes, attributeChangeListener);
    }

    @Override
    public Attributes getAttributes() {
        return attributes;
    }

    @Override
    public UserModel getUser() {
        return user;
    }

    private LegacyUserProfile addAttributeValidator(String name, String message,
            BiFunction<List<String>, UserProfile, Boolean> validator) {
        attributes.addValidator(name, message, validator);
        return this;
    }

    private void updateAttributes(Map<String, List<String>> attributes, boolean removeMissingAttributes,
            BiConsumer<String, UserModel>[] attributeChangeListener) {
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
        if (removeMissingAttributes) {
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

    private static void filterAttributes(DefaultContextKey userUpdateEvent, RealmModel realm, Map<String, List<String>> attributes) {
        //The Idp review does not respect "isEditUserNameAllowed" therefore we have to miss the check here
        if (!userUpdateEvent.equals(DefaultContextKey.IDP_REVIEW)) {
            //This step has to be done before email is assigned to the username if isRegistrationEmailAsUsername is set
            //Otherwise email change will not reflect in username changes.
            if (attributes.get(UserModel.USERNAME) != null && !realm.isEditUsernameAllowed()) {
                attributes.remove(UserModel.USERNAME);
            }
        }

        if (attributes.get(UserModel.EMAIL) != null && attributes.get(UserModel.EMAIL).isEmpty()) {
            attributes.remove(UserModel.EMAIL);
            attributes.put(UserModel.EMAIL, Collections.singletonList(null));
        }

        if (attributes.get(UserModel.EMAIL) != null && realm.isRegistrationEmailAsUsername()) {
            attributes.remove(UserModel.USERNAME);
            attributes.put(UserModel.USERNAME, attributes.get(UserModel.EMAIL));
        }
    }

    private static List<String> AttributeToLower(List<String> attr) {
        if (attr.size() == 1 && attr.get(0) != null)
            return Collections.singletonList(KeycloakModelUtils.toLowerCaseSafe(attr.get(0)));
        return attr;
    }

    private void addUserCreationValidators() {
        RealmModel realm = this.session.getContext().getRealm();

        if (realm.isRegistrationEmailAsUsername()) {
            addAttributeValidator(UserModel.EMAIL, Messages.INVALID_EMAIL, StaticValidators.isEmailValid())
                    .addAttributeValidator(UserModel.EMAIL, Messages.MISSING_EMAIL, StaticValidators.isBlank())
                    .addAttributeValidator(UserModel.EMAIL, Messages.EMAIL_EXISTS, StaticValidators.doesEmailExist(session));


        } else {
            addAttributeValidator(UserModel.USERNAME, Messages.MISSING_USERNAME, StaticValidators.isBlank())
                    .addAttributeValidator(UserModel.USERNAME, Messages.USERNAME_EXISTS,
                            (value, o) -> session.users().getUserByUsername(realm, value.get(0)) == null);
        }
    }

    private void addBasicValidators(boolean userNameExistsCondition) {

        addAttributeValidator(UserModel.USERNAME, Messages.MISSING_USERNAME, StaticValidators.checkUsernameExists(userNameExistsCondition))
                .addAttributeValidator(UserModel.FIRST_NAME, Messages.MISSING_FIRST_NAME, StaticValidators.isBlank())
                .addAttributeValidator(UserModel.LAST_NAME, Messages.MISSING_LAST_NAME, StaticValidators.isBlank())
                .addAttributeValidator(UserModel.EMAIL, Messages.MISSING_EMAIL, StaticValidators.isBlank())
                .addAttributeValidator(UserModel.EMAIL, Messages.INVALID_EMAIL, StaticValidators.isEmailValid());
    }

    private void addSessionValidators() {
        RealmModel realm = this.session.getContext().getRealm();
        addAttributeValidator(UserModel.USERNAME, Messages.USERNAME_EXISTS, StaticValidators.userNameExists(session))
                .addAttributeValidator(UserModel.USERNAME, Messages.READ_ONLY_USERNAME, StaticValidators.isUserMutable(realm))
                .addAttributeValidator(UserModel.EMAIL, Messages.EMAIL_EXISTS, StaticValidators.isEmailDuplicated(session))
                .addAttributeValidator(UserModel.EMAIL, Messages.USERNAME_EXISTS, StaticValidators.doesEmailExistAsUsername(session));
    }

    private void addReadOnlyAttributeValidators(Pattern configuredReadOnlyAttrs, Map<String, List<String>> attributes) {
        addValidatorsForReadOnlyAttributes(configuredReadOnlyAttrs, attributes);
        if (user != null) {
            addValidatorsForReadOnlyAttributes(configuredReadOnlyAttrs, user.getAttributes());
        }
    }


    private void addValidatorsForReadOnlyAttributes(Pattern configuredReadOnlyAttrsPattern, Map<String, List<String>> attributes) {
        attributes.keySet().stream()
                .filter(currentAttrName -> configuredReadOnlyAttrsPattern.matcher(currentAttrName).find())
                .forEach((currentAttrName) ->
                        addAttributeValidator(currentAttrName, Messages.UPDATE_READ_ONLY_ATTRIBUTES_REJECTED, StaticValidators.isReadOnlyAttributeUnchanged(currentAttrName))
                );
    }
}
