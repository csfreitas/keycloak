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

import org.jboss.logging.Logger;
import org.keycloak.common.util.ObjectUtil;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.validation.Validation;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Functions are supposed to return:
 * - true if validation success
 * - false if validation fails
 *
 * @author <a href="mailto:markus.till@bosch.io">Markus Till</a>
 */
public class StaticValidators {

    private static final Logger logger = Logger.getLogger(StaticValidators.class);

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

    public static Validator isReadOnlyAttributeUnchanged(Pattern pattern) {
        return (attribute, user) -> {
            String key = attribute.getKey();

            if (!pattern.matcher(key).find()) {
                return true;
            }

            List<String> values = attribute.getValue();

            if (values == null) {
                return true;
            }

            List<String> existingAttrValues = user == null ? null : user.getAttribute(key);
            String existingValue = null;

            if (existingAttrValues != null && !existingAttrValues.isEmpty()) {
                existingValue = existingAttrValues.get(0);
            }

            if (values.isEmpty() && existingValue != null) {
                return false;
            }

            String value = null;

            if (!values.isEmpty()) {
                value = values.get(0);
            }

            boolean result = ObjectUtil.isEqualOrBothNull(value, existingValue);

            if (!result) {
                logger.warnf("Attempt to edit denied attribute '%s' of user '%s'", pattern, user == null ? "new user" : user.getFirstAttribute(UserModel.USERNAME));
            }

            return result;
        };
    }

}
