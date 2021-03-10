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

package org.keycloak.userprofile.legacy;

import org.jboss.logging.Logger;
import org.keycloak.common.util.ObjectUtil;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.userprofile.validation.AttributeValidator;
import org.keycloak.userprofile.validation.Validator;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Functions are supposed to return:
 * - true if validation success
 * - false if validation fails
 *
 * @author <a href="mailto:markus.till@bosch.io">Markus Till</a>
 */
public class Validators {

    private static final Logger logger = Logger.getLogger(Validators.class);

    private static AttributeValidator addAttributeValidator(String name, String message, Validator validator) {
        return new AttributeValidator(name, message, validator);
    }

    public static List<AttributeValidator> addUserCreationValidators(KeycloakSession session) {
        RealmModel realm = session.getContext().getRealm();

        if (realm.isRegistrationEmailAsUsername()) {
            return Arrays.asList(addAttributeValidator(UserModel.EMAIL, Messages.INVALID_EMAIL, Validators.isEmailValid()),
                    addAttributeValidator(UserModel.EMAIL, Messages.MISSING_EMAIL, Validators.isBlank()),
                    addAttributeValidator(UserModel.EMAIL, Messages.EMAIL_EXISTS, Validators.doesEmailExist(session)));
        }

        return Arrays.asList(addAttributeValidator(UserModel.USERNAME, Messages.MISSING_USERNAME, Validators.isBlank()),
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

    public static List<AttributeValidator> addBasicValidators(boolean userNameExistsCondition) {
        return Arrays.asList(addAttributeValidator(UserModel.USERNAME, Messages.MISSING_USERNAME, Validators.checkUsernameExists(userNameExistsCondition)),
                addAttributeValidator(UserModel.FIRST_NAME, Messages.MISSING_FIRST_NAME, Validators.isBlank()),
                addAttributeValidator(UserModel.LAST_NAME, Messages.MISSING_LAST_NAME, Validators.isBlank()),
                addAttributeValidator(UserModel.EMAIL, Messages.MISSING_EMAIL, Validators.isBlank()),
                addAttributeValidator(UserModel.EMAIL, Messages.INVALID_EMAIL, Validators.isEmailValid()));
    }

    public static List<AttributeValidator> addSessionValidators(KeycloakSession session) {
        RealmModel realm = session.getContext().getRealm();
        return Arrays.asList(addAttributeValidator(UserModel.USERNAME, Messages.USERNAME_EXISTS, Validators.userNameExists(session)),
                addAttributeValidator(UserModel.USERNAME, Messages.READ_ONLY_USERNAME, Validators.isUserMutable(realm)),
                addAttributeValidator(UserModel.EMAIL, Messages.EMAIL_EXISTS, Validators.isEmailDuplicated(session)),
                addAttributeValidator(UserModel.EMAIL, Messages.USERNAME_EXISTS, Validators.doesEmailExistAsUsername(session)));
    }

    public static Validator isBlank() {
        return (attribute, context) -> {
            List<String> values = attribute.getValue();

            if (values.isEmpty()) {
                return true;
            }

            String value = values.get(0);

            return value == null || !Validation.isBlank(value);
        };
    }

    public static Validator isEmailValid() {
        return (attribute, user) -> {
            List<String> values = attribute.getValue();

            if (values.isEmpty()) {
                return true;
            }

            String value = values.get(0);

            return Validation.isBlank(value) || Validation.isEmailValid(value);
        };
    }

    public static Validator userNameExists(KeycloakSession session) {
        return (attribute, user) -> {
            List<String> values = attribute.getValue();

            if (values.isEmpty()) {
                return true;
            }

            String value = values.get(0);

            if (Validation.isBlank(value)) return true;

            return !(user != null
                    && !value.equals(user.getFirstAttribute(UserModel.USERNAME))
                    && session.users().getUserByUsername(session.getContext().getRealm(), value) != null);
        };
    }

    public static Validator isUserMutable(RealmModel realm) {
        return (attribute, user) -> {
            List<String> values = attribute.getValue();

            if (values.isEmpty()) {
                return true;
            }

            String value = values.get(0);

            if (Validation.isBlank(value)) return true;

            return !(!realm.isEditUsernameAllowed()
                        && user != null
                        && !value.equals(user.getFirstAttribute(UserModel.USERNAME))
                );
        };
    }

    public static Validator checkUsernameExists(boolean externalCondition) {
        return (attribute, user) -> {
            List<String> values = attribute.getValue();
            String value = values.get(0);

            return !(externalCondition && Validation.isBlank(value));
        };
    }


    public static Validator doesEmailExistAsUsername(KeycloakSession session) {
        return (attribute, user) -> {
            List<String> values = attribute.getValue();

            if (values.isEmpty()) {
                return true;
            }

            String value = values.get(0);

            if (Validation.isBlank(value)) return true;

            RealmModel realm = session.getContext().getRealm();

            if (!realm.isDuplicateEmailsAllowed()) {
                UserModel userByEmail = session.users().getUserByEmail(realm, value);
                return !(realm.isRegistrationEmailAsUsername() && userByEmail != null && user != null && !userByEmail.getId().equals(user.getId()));
            }
            return true;
        };
    }

    public static Validator isEmailDuplicated(KeycloakSession session) {
        return (attribute, user) -> {
            List<String> values = attribute.getValue();

            if (values.isEmpty()) {
                return true;
            }

            String value = values.get(0);

            if (Validation.isBlank(value)) return true;

            RealmModel realm = session.getContext().getRealm();

            if (!realm.isDuplicateEmailsAllowed()) {
                UserModel userByEmail = session.users().getUserByEmail(realm, value);
                // check for duplicated email
                return !(userByEmail != null && (user == null || !userByEmail.getId().equals(user.getId())));
            }
            return true;
        };
    }

    public static Validator doesEmailExist(KeycloakSession session) {
        return (attribute, user) -> {
            List<String> values = attribute.getValue();
            String value = values.get(0);

            return !(value != null
                    && !session.getContext().getRealm().isDuplicateEmailsAllowed()
                    && session.users().getUserByEmail(session.getContext().getRealm(), value) != null);
        };
    }
}
