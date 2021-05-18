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
package org.keycloak.validate;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

import org.keycloak.models.KeycloakSession;
import org.keycloak.validate.validators.NotBlankValidator;
import org.keycloak.validate.validators.NotEmptyValidator;
import org.keycloak.validate.validators.ValidatorConfigValidator;

/**
 * Base class for arbitrary value type validators. Functionality covered in this base class:
 * <ul>
 * <li>accepts supported type, collection of supported type. Also accepts plain string and collections of strings as
 * input if not disabled by {@link #KEY_STRING_DISABLED} config option.
 * <li>string values are converted to supported type by
 * {@link #convertStringValue(String, String, ValidationContext, ValidatorConfig)}
 * <li>each item is validated for collections if not disabled by {@value #KEY_COLLECTION_DISABLED} config option, see
 * {@link #validateValue(Object, String, ValidationContext, ValidatorConfig)}
 * <li>validation stops after first error for collections
 * <li>null values and empty String are always treated as valid to support optional fields! Use other validators (like
 * {@link NotBlankValidator} or {@link NotEmptyValidator} to force field as required.
 * </ul>
 * 
 * @author Vlastimil Elias <velias@redhat.com>
 *
 */
public abstract class SimpleValueValidatorBase implements SimpleValidator {

	/**
	 * Configuration key - boolean. If <code>true</code> then String value is not allowed (validation fails for them).
	 */
	public static final String KEY_STRING_DISABLED = "string-disabled";

	/**
	 * Configuration key - boolean. If <code>true</code> then Collection value is not allowed (validation fails for them).
	 */
	public static final String KEY_COLLECTION_DISABLED = "collection-disabled";

	private final String invalidTypeMessage;

	/**
	 * @param invalidTypeMessage message used to report invalid type
	 */
	public SimpleValueValidatorBase(String invalidTypeMessage) {
		this.invalidTypeMessage = invalidTypeMessage;
	}

	@Override
	public ValidationContext validate(Object input, String inputHint, ValidationContext context, ValidatorConfig config) {

		if (input != null) {
			if (isStringAllowed(context,config) && input instanceof String) {
				validateStringValue(input, inputHint, context, config);
			} else if (isSupportedClass(input, inputHint, context, config)) {
				validateValue(input, inputHint, context, config);
			} else if (isCollectionAllowed(context, config) && input instanceof Collection) {
				@SuppressWarnings("unchecked")
				Collection<Object> values = (Collection<Object>) input;
				if (!values.isEmpty()) {
					for (Object value : values) {
						if (value != null) {
							if (isStringAllowed(context, config) && value instanceof String) {
								if (!validateStringValue(value, inputHint, context, config))
									return context;
							} else if (isSupportedClass(value, inputHint, context, config)) {
								if (!validateValue(value, inputHint, context, config)) {
									return context;
								}
							} else {
								context.addError(new ValidationError(getId(), inputHint, invalidTypeMessage, input));
								return context;
							}
						}
					}
				}
			} else {
				context.addError(new ValidationError(getId(), inputHint, invalidTypeMessage, input));
			}
		}
		return context;
	}

	protected boolean isStringAllowed(ValidationContext context, ValidatorConfig config) {
		return config == null || !config.getBooleanOrDefault(KEY_STRING_DISABLED, false);
	}

	protected boolean isCollectionAllowed(ValidationContext context, ValidatorConfig config) {
		return config == null || !config.getBooleanOrDefault(KEY_COLLECTION_DISABLED, false);
	}

	private boolean validateStringValue(Object input, String inputHint, ValidationContext context, ValidatorConfig config) {
		if(((String) input).length() == 0) {
			return true;
		}
		Object val = convertStringValue((String) input, inputHint, context, config);
		if (val == null) {
			context.addError(new ValidationError(getId(), inputHint, invalidTypeMessage, input));
			return false;
		} else {
			return validateValue(val, inputHint, context, config);
		}
	}

	/**
	 * Check that value type is supported by this validator - type must be accepted by
	 * {@link #validateValue(Object, String, ValidationContext, ValidatorConfig)} then.
	 * 
	 * @param value to check type for, never null
	 * @return true if type of the value is supported by
	 *         {@link #validateValue(Object, String, ValidationContext, ValidatorConfig)}. Error is reported if false is
	 *         returned.
	 */
	protected abstract boolean isSupportedClass(Object value, String inputHint, ValidationContext context, ValidatorConfig config);

	/**
	 * Convert String value to target value type to be validated (type must be accepted by
	 * {@link #validateValue(Object, String, ValidationContext, ValidatorConfig)} then).
	 * 
	 * @param value String value to be converted to target type for validation, never null
	 * @param inputHint
	 * @param context
	 * @param config
	 * @return converted value or null if not convertible (error is produced in this case by calling code, no need to
	 *         report it here)
	 */
	protected abstract Object convertStringValue(String value, String inputHint, ValidationContext context, ValidatorConfig config);

	/**
	 * Validate format/range of the value. Always use {@link ValidationContext#addError(ValidationError)} to report
	 * error to the user!
	 * 
	 * @param value to be validated, never null
	 * @param inputHint
	 * @param context for the validation. Add errors into it.
	 * @param config of the validation if provided
	 * @return true if value is valid, false if it is invalid (used to control Collection validation process only,
	 *         always add error into context in this case)
	 */
	protected abstract boolean validateValue(Object value, String inputHint, ValidationContext context, ValidatorConfig config);

	@Override
	public ValidationResult validateConfig(KeycloakSession session, ValidatorConfig config) {

		if (config != null) {
			if (config.containsKey(KEY_STRING_DISABLED) && (config.getBoolean(KEY_STRING_DISABLED) == null)) {
				Set<ValidationError> errors = new LinkedHashSet<>();
				errors.add(new ValidationError(getId(), KEY_STRING_DISABLED, ValidatorConfigValidator.MESSAGE_CONFIG_INVALID_BOOLEAN_VALUE, config.get(KEY_STRING_DISABLED)));
				return new ValidationResult(errors);
			}
		}
		return ValidationResult.OK;
	}
}
