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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.common.util.ObjectUtil;
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

    private static final Logger logger = Logger.getLogger(DefaultAttributes.class);

    private static String UPDATE_READ_ONLY_ATTRIBUTES_REJECTED = "updateReadOnlyAttributesRejectedMessage";

    private static String[] DEFAULT_READ_ONLY_ATTRIBUTES = { "KERBEROS_PRINCIPAL", "LDAP_ID", "LDAP_ENTRY_DN", "CREATED_TIMESTAMP", "createTimestamp", "modifyTimestamp", "userCertificate", "saml.persistent.name.id.for.*", "ENABLED", "EMAIL_VERIFIED" };
    private static String[] DEFAULT_ADMIN_READ_ONLY_ATTRIBUTES = { "KERBEROS_PRINCIPAL", "LDAP_ID", "LDAP_ENTRY_DN", "CREATED_TIMESTAMP", "createTimestamp", "modifyTimestamp" };

    private static Pattern readOnlyAttributesPattern = getRegexPatternString(DEFAULT_READ_ONLY_ATTRIBUTES);
    private static Pattern adminReadOnlyAttributesPattern = getRegexPatternString(DEFAULT_ADMIN_READ_ONLY_ATTRIBUTES);

    private static Predicate<String> readOnlyPredicate = attributeName -> adminReadOnlyAttributesPattern.matcher(attributeName).find()
                || readOnlyAttributesPattern.matcher(attributeName).find();

    private final ContextKey context;
    private final UserModel user;
    private final KeycloakSession session;
    private Map<String, List<AttributeValidator>> validators = new HashMap<>();

    public DefaultAttributes(ContextKey context, Map<String, ?> attributes, UserModel user,
            Map<ContextKey, Function<KeycloakSession, List<AttributeValidator>>> validatorByContext, KeycloakSession session) {
        this.context = context;
        this.user = user;
        this.session = session;

        putAll(transformAttributes(attributes));

        Function<KeycloakSession, List<AttributeValidator>> contextValidators = validatorByContext.get(context);

        if (contextValidators != null) {
            for (AttributeValidator validator : contextValidators.apply(session)) {
                addValidator(validator);
            }
        }

        if (UserProfile.DefaultContextKey.USER_RESOURCE.equals(context)) {
            addValidator(new AttributeValidator("*", UPDATE_READ_ONLY_ATTRIBUTES_REJECTED, isReadOnlyAttributeUnchanged(adminReadOnlyAttributesPattern)));
        } else {
            addValidator(new AttributeValidator("*", UPDATE_READ_ONLY_ATTRIBUTES_REJECTED, isReadOnlyAttributeUnchanged(readOnlyAttributesPattern)));
        }
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
        return readOnlyPredicate.test(key);
    }

    @Override
    public boolean validate(Map.Entry<String, List<String>> attribute, Consumer<String> error) {
        boolean success = true;
        List<AttributeValidator> validators = this.validators.getOrDefault(attribute.getKey(), new ArrayList<>());

        validators.addAll(this.validators.getOrDefault("*", Collections.emptyList()));

        for (AttributeValidator validator : validators) {
            if (!validator.getValidator().validate(attribute, user)) {
                error.accept(validator.getMessage());
                success = false;
            }
        }

        return success;
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

        if (isReadOnlyAttribute(name)) {
            return true;
        }

        // checks whether the attribute is expected when managing the user profile using forms
        return UserModel.USERNAME.equals(name) || UserModel.EMAIL.equals(name) || UserModel.LAST_NAME.equals(name) || UserModel.FIRST_NAME.equals(name);
    }

    private static Pattern getRegexPatternString(String[] builtinReadOnlyAttributes) {
        List<String> readOnlyAttributes = new ArrayList<>(Arrays.asList(builtinReadOnlyAttributes));

        String regexStr = readOnlyAttributes.stream()
                .map(configAttrName -> configAttrName.endsWith("*")
                        ? "^" + Pattern.quote(configAttrName.substring(0, configAttrName.length() - 1)) + ".*$"
                        : "^" + Pattern.quote(configAttrName ) + "$")
                .collect(Collectors.joining("|"));
        regexStr = "(?i:" + regexStr + ")";

        return Pattern.compile(regexStr);
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
