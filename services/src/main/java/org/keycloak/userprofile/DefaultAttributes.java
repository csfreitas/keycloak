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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.regex.Pattern;

import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.userprofile.validation.AttributeValidator;
import org.keycloak.userprofile.validation.Validator;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class DefaultAttributes extends HashMap<String, List<String>> implements UserProfile.Attributes {

    private final UserProfile.DefaultContextKey context;
    private final UserModel user;
    private final Pattern adminReadOnlyAttributes;
    private final Pattern readOnlyAttributes;
    private final KeycloakSession session;
    private Map<String, List<AttributeValidator>> validators = new HashMap<>();

    public DefaultAttributes(UserProfile.DefaultContextKey context, Map<String, ?> attributes, UserModel user,
            Pattern adminReadOnlyAttributes,
            Pattern readOnlyAttributes, KeycloakSession session) {
        this.context = context;
        this.user = user;
        this.adminReadOnlyAttributes = adminReadOnlyAttributes;
        this.readOnlyAttributes = readOnlyAttributes;
        this.session = session;
        putAll(transformAttributes(attributes));
    }

    @Override
    public String getFirstValue(String name) {
        List<String> values = getOrDefault(name, Collections.emptyList());

        if (values.isEmpty()) {
            return null;
        }

        return values.get(0);
    }

    @Override
    public boolean isReadOnlyAttribute(String key) {
        return adminReadOnlyAttributes.matcher(key).find() || readOnlyAttributes.matcher(key).find();
    }

    @Override
    public boolean validate(Map.Entry<String, List<String>> attribute, Consumer<String> error) {
        boolean status = true;
        List<AttributeValidator> validators = this.validators.getOrDefault(attribute.getKey(), new ArrayList<>());

        validators.addAll(this.validators.getOrDefault("*", Collections.emptyList()));

        for (AttributeValidator validator : validators) {
            if (!validator.getValidator().validate(attribute, user)) {
                error.accept(validator.getMessage());
                status = false;
            }
        }

        return status;
    }

    void addValidator(AttributeValidator validator) {
        validators.computeIfAbsent(validator.getAttributeName(), s -> new ArrayList<>()).add(validator);
    }

    private void filterAttributes(RealmModel realm, Map<String, List<String>> attributes) {
        //The Idp review does not respect "isEditUserNameAllowed" therefore we have to miss the check here
        if (!context.equals(UserProfile.DefaultContextKey.IDP_REVIEW)) {
            //This step has to be done before email is assigned to the username if isRegistrationEmailAsUsername is set
            //Otherwise email change will not reflect in username changes.
            if (attributes.get(UserModel.USERNAME) != null && !realm.isEditUsernameAllowed()) {
                if (context.equals(UserProfile.DefaultContextKey.USER_RESOURCE)) {
                    attributes.remove(UserModel.USERNAME);
                }
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

    private Map<String, List<String>> transformAttributes(Map<String, ?> attributes) {
        Map<String, List<String>> newAttributes = Collections.emptyMap();

        if (attributes != null && !attributes.isEmpty()) {
            newAttributes = new HashMap<>();
            for (Map.Entry<String, ?> entry : attributes.entrySet()) {
                Object value = entry.getValue();
                String key = entry.getKey();

                if (!isSupportedAttribute(key)) {
                    continue;
                }

                if (key.startsWith(Constants.USER_ATTRIBUTES_PREFIX)) {
                    key = key.substring(Constants.USER_ATTRIBUTES_PREFIX.length());
                }

                if (value instanceof String) {
                    newAttributes.put(key, Collections.singletonList((String) value));
                } else {
                    newAttributes.put(key, (List<String>) value);
                }
            }
        }

        filterAttributes(session.getContext().getRealm(), newAttributes);

        return newAttributes;
    }

    private boolean isSupportedAttribute(String name) {
        // expect any attribute if managing the user profile using REST
        if (UserProfile.DefaultContextKey.USER_RESOURCE.equals(context) || UserProfile.DefaultContextKey.ACCOUNT.equals(context)) {
            return true;
        }

        // attributes managed using forms with a pre-defined prefix are supported
        if (name.startsWith(Constants.USER_ATTRIBUTES_PREFIX)) {
            return true;
        }

        if (adminReadOnlyAttributes.matcher(name).find() || readOnlyAttributes.matcher(name).find()) {
            return true;
        }

        // checks whether the attribute is expected when managing the user profile using forms
        return UserModel.USERNAME.equals(name) || UserModel.EMAIL.equals(name) || UserModel.LAST_NAME.equals(name) || UserModel.FIRST_NAME.equals(name);
    }
}
