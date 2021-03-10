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
import org.keycloak.userprofile.UserProfile;

import java.util.List;
import java.util.function.BiFunction;

/**
 * Functions are supposed to return:
 * - true if validation success
 * - false if validation fails
 *
 * @author <a href="mailto:markus.till@bosch.io">Markus Till</a>
 */
public class StaticValidators {

    private static final Logger logger = Logger.getLogger(StaticValidators.class);

    public static BiFunction<List<String>, UserProfile, Boolean> isBlank() {
        return (value, context) ->
                value==null || !Validation.isBlank(value.get(0));
    }

    public static BiFunction<List<String>, UserProfile, Boolean> isEmailValid() {
        return (value, context) ->
                Validation.isBlank(value.get(0)) || Validation.isEmailValid(value.get(0));
    }

    public static BiFunction<List<String>, UserProfile, Boolean> userNameExists(KeycloakSession session) {
        return (value, context) -> {
            if (Validation.isBlank(value.get(0))) return true;
            return !(context.getUser() != null
                    && !value.get(0).equals(context.getUser().getFirstAttribute(UserModel.USERNAME))
                    && session.users().getUserByUsername(session.getContext().getRealm(), value.get(0)) != null);
        };
    }

    public static BiFunction<List<String>, UserProfile, Boolean> isUserMutable(RealmModel realm) {
        return (value, context) -> {
            if (Validation.isBlank(value.get(0))) return true;
            return !(!realm.isEditUsernameAllowed()
                        && context.getUser() != null
                        && !value.get(0).equals(context.getUser().getFirstAttribute(UserModel.USERNAME))
                );
        };
    }

    public static BiFunction<List<String>, UserProfile, Boolean> checkUsernameExists(boolean externalCondition) {
        return (value, context) ->
                !(externalCondition && Validation.isBlank(value.get(0)));
    }


    public static BiFunction<List<String>, UserProfile, Boolean> doesEmailExistAsUsername(KeycloakSession session) {
        return (value, context) -> {
            if (Validation.isBlank(value.get(0))) return true;
            RealmModel realm = session.getContext().getRealm();
            if (!realm.isDuplicateEmailsAllowed()) {
                UserModel userByEmail = session.users().getUserByEmail(realm, value.get(0));
                return !(realm.isRegistrationEmailAsUsername() && userByEmail != null && context.getUser() != null && !userByEmail.getId().equals(context.getUser().getId()));
            }
            return true;
        };
    }

    public static BiFunction<List<String>, UserProfile, Boolean> isEmailDuplicated(KeycloakSession session) {
        return (value, context) -> {
            if (Validation.isBlank(value.get(0))) return true;
            RealmModel realm = session.getContext().getRealm();
            if (!realm.isDuplicateEmailsAllowed()) {
                UserModel userByEmail = session.users().getUserByEmail(realm, value.get(0));
                // check for duplicated email
                return !(userByEmail != null && (context.getUser() == null || !userByEmail.getId().equals(context.getUser().getId())));
            }
            return true;
        };
    }

    public static BiFunction<List<String>, UserProfile, Boolean> doesEmailExist(KeycloakSession session) {
        return (value, context) ->
                !(value != null
                        && !session.getContext().getRealm().isDuplicateEmailsAllowed()
                        && session.users().getUserByEmail(session.getContext().getRealm(), value.get(0)) != null);
    }

    public static BiFunction<List<String>, UserProfile, Boolean> isReadOnlyAttributeUnchanged(String attributeName) {
        return (newAttrValues, context) -> {
            if (newAttrValues == null) {
                return true;
            }
            List<String> existingAttrValues = context.getUser() == null ? null : context.getUser().getAttribute(attributeName);
            String existingValue = null;

            if (existingAttrValues != null && !existingAttrValues.isEmpty()) {
                existingValue = existingAttrValues.get(0);
            }

            String value = null;

            if (!newAttrValues.isEmpty()) {
                value = newAttrValues.get(0);
            }

            boolean result = ObjectUtil.isEqualOrBothNull(value, existingValue);

            if (!result) {
                logger.warnf("Attempt to edit denied attribute '%s' of user '%s'", attributeName, context.getUser() == null ? "new user" : context.getUser().getFirstAttribute(UserModel.USERNAME));
            }
            return result;
        };
    }

}
