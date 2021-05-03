/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.testsuite.user.profile.config;

import static org.keycloak.common.util.ObjectUtil.isBlank;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import org.keycloak.util.JsonSerialization;

/**
 * Parser of the User Profile JSON configuration to object representation with consistency validations. Main methods to use:
 * <ul>
 * <li>{@link #readConfig(InputStream)}
 * <li>{@link #validateConfiguration(UPConfig)}
 * </ul>
 * 
 * @author Vlastimil Elias <velias@redhat.com>
 *
 */
public class UPConfigParser {

    public static final String ROLE_USER = "user";
    public static final String ROLE_ADMIN = "admin";

    /**
     * Load configuration from JSON file.
     * <p>
     * Configuration is not validated, use {@link #validateConfiguration(UPConfig)} to validate it and get list of errors.
     * 
     * @param is JSON file to be loaded
     * @return object representation of the configuration
     * @throws IOException if JSON configuration can't be loaded (eg due to JSON format errors etc)
     */
    public static UPConfig readConfig(InputStream is) throws IOException {
        return JsonSerialization.readValue(is, UPConfig.class);
    }

    /**
     * Validate object representation of the configuration. Validations:
     * <ul>
     * <li>defaultProfile is defined and exists in profiles
     * <li>parent exists for type
     * <li>type exists for attribute
     * <li>validator (from Validator SPI) exists for validation and it's config is correct
     * </ul>
     * 
     * @param config to validate
     * @return list of errors, empty if no error found
     */
    public static List<String> validateConfiguration(UPConfig config) {
        List<String> errors = new ArrayList<>();

        if (config.getAttributes() != null) {
            Set<String> attNamesCache = new HashSet<>();
            config.getAttributes().forEach((attribute) -> validateAttributeConfig(attribute, config, errors, attNamesCache));
        } else {
            errors.add("UserProfile configuration without 'attributes' section is not allowed");
        }

        return errors;
    }

    protected static final Set<String> PSEUDOROLES = new HashSet<>();
    static {
        PSEUDOROLES.add(ROLE_ADMIN);
        PSEUDOROLES.add(ROLE_USER);
    }

    /**
     * Validate attribute configuration
     * 
     * @param attributeConfig config to be validated
     * @param config whole configuration to be used for validation
     * @param errors to add error message in if something is invalid
     */
    protected static void validateAttributeConfig(UPAttribute attributeConfig, UPConfig config, List<String> errors, Set<String> attNamesCache) {
        String attributeName = attributeConfig.getName();
        if (isBlank(attributeName)) {
            errors.add("Attribute configuration without 'name' is not allowed");
        } else {
            if (attNamesCache.contains(attributeName)) {
                errors.add("Duplicit attribute configuration with 'name':'" + attributeName + "'");
            } else {
                attNamesCache.add(attributeName);
                if(!attributeNameIsValid(attributeName)) {
                    errors.add("Invalid attribute name (only letters, numbers and '.' '_' '-' special characters allowed): " + attributeName + "'");
                }
            }
        }
        if (attributeConfig.getValidations() != null) {
            attributeConfig.getValidations().forEach(validation -> validateValidationConfig(validation, attributeName, errors));
        }
        if (attributeConfig.getPermissions() != null) {
            if (attributeConfig.getPermissions().getView() == null) {
                errors.add("'permissions.view' configuration is not defined for attribute '" + attributeName + "'");
            } else {
                validateRoles(attributeConfig.getPermissions().getView(), "permissions.view", errors, attributeName);
            }
            if (attributeConfig.getPermissions().getEdit() == null) {
                errors.add("'permissions.edit' configuration is not defined for attribute '" + attributeName + "'");
            } else {
                validateRoles(attributeConfig.getPermissions().getEdit(), "permissions.edit", errors, attributeName);
            }
        }
        if (attributeConfig.getRequirements() != null) {
            validateRoles(attributeConfig.getRequirements().getRoles(), "requirements.roles", errors, attributeName);
        }
    }

    /**
     * @param attributeName to validate
     * @return
     */
    protected static boolean attributeNameIsValid(String attributeName) {
        return Pattern.matches("[a-zA-Z0-9\\._\\-]+", attributeName);
    }

    /**
     * Validate list of configured roles - must contain only supported {@link #PSEUDOROLES} for now.
     * 
     * @param roles to validate
     * @param fieldName we are validating for use in error messages
     * @param errors to ass error message into
     * @param attributeName we are validating for use in erorr messages
     */
    private static void validateRoles(List<String> roles, String fieldName, List<String> errors, String attributeName) {
        if (roles != null) {
            for (String role : roles) {
                if (!PSEUDOROLES.contains(role)) {
                    errors.add("'" + fieldName + "' configuration for attribute '" + attributeName + "' contains unsupported role '" + role + "'");
                }
            }
        }
    }

    /**
     * Validate that validation configuration is correct
     * 
     * @param validationConfig config to be checked
     * @param errors to add error message in if something is invalid
     */
    protected static void validateValidationConfig(UPAttributeValidation validationConfig, String attributeName, List<String> errors) {

        String validator = validationConfig.getValidator();
        if (isBlank(validator)) {
            errors.add("Validation without 'validator' is defined for attribute '" + attributeName + "'");
        } else {
            // TODO UserProfile - Validation SPI integration - check that the validator exists using Validation SPI
            // TODO UserProfile - Validation SPI integration - check that the validation configuration is correct for given validator using Validation SPI
        }
    }
}
