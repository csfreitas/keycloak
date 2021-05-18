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
package org.keycloak.validate.validators;

import java.util.LinkedHashSet;
import java.util.Set;

import org.keycloak.models.KeycloakSession;
import org.keycloak.validate.SimpleValueValidatorBase;
import org.keycloak.validate.ValidationContext;
import org.keycloak.validate.ValidationError;
import org.keycloak.validate.ValidationResult;
import org.keycloak.validate.ValidatorConfig;

/**
 * Validate input being integer number ( {@link Long} and {@link Integer}). Accepts String also if convertible to
 * {@link Long}. Allows to check min and max value of the number if configured using {@link #KEY_MIN} and
 * {@link #KEY_MAX}.
 * 
 * @author Vlastimil Elias <velias@redhat.com>
 */
public class IntegerNumberValidator extends SimpleValueValidatorBase {

	public static final String ID = "number-integer";

	public static final String MESSAGE_INVALID_INTEGER_NUMBER = "error-invalid-integer-number";
	public static final String MESSAGE_INTEGER_NUMBER_OUT_OF_RANGE = "error-integer-number-out-of-range";

	public static final String KEY_MIN = "min";
	public static final String KEY_MAX = "max";

	public static final IntegerNumberValidator INSTANCE = new IntegerNumberValidator();

	private IntegerNumberValidator() {
		super(MESSAGE_INVALID_INTEGER_NUMBER);
	}

	@Override
	public String getId() {
		return ID;
	}

	@Override
	protected boolean isSupportedClass(Object value, String inputHint, ValidationContext context, ValidatorConfig config) {
		return (value instanceof Integer) || (value instanceof Long);
	}

	@Override
	protected Object convertStringValue(String value, String inputHint, ValidationContext context, ValidatorConfig config) {
		try {
			return new Long(value.trim());
		} catch (NumberFormatException nfe2) {
			return null;
		}
	}

	@Override
	protected boolean validateValue(Object value, String inputHint, ValidationContext context, ValidatorConfig config) {
		long val = ((Number) value).longValue();

		Long min = config.getLong(KEY_MIN);
		Long max = config.getLong(KEY_MAX);

		if (min != null && val < min.longValue()) {
			context.addError(new ValidationError(ID, inputHint, MESSAGE_INTEGER_NUMBER_OUT_OF_RANGE, value, min, max));
			return false;
		}

		if (max != null && val > max.longValue()) {
			context.addError(new ValidationError(ID, inputHint, MESSAGE_INTEGER_NUMBER_OUT_OF_RANGE, value, min, max));
			return false;
		}

		return true;
	}

	@Override
	public ValidationResult validateConfig(KeycloakSession session, ValidatorConfig config) {
		Set<ValidationError> errors = new LinkedHashSet<>();
		if (config != null) {
			boolean containsMin = config.containsKey(KEY_MIN);
			boolean containsMax = config.containsKey(KEY_MAX);

			if (containsMin && config.getLong(KEY_MIN) == null) {
				errors.add(new ValidationError(ID, KEY_MIN, ValidatorConfigValidator.MESSAGE_CONFIG_INVALID_INTEGER_VALUE, config.get(KEY_MIN)));
			}

			if (containsMax && config.getLong(KEY_MAX) == null) {
				errors.add(new ValidationError(ID, KEY_MAX, ValidatorConfigValidator.MESSAGE_CONFIG_INVALID_INTEGER_VALUE, config.get(KEY_MAX)));
			}

			if (errors.isEmpty() && containsMin && containsMax && (config.getInt(KEY_MIN) >= config.getInt(KEY_MAX))) {
				errors.add(new ValidationError(ID, KEY_MAX, ValidatorConfigValidator.MESSAGE_CONFIG_INVALID_VALUE));
			}
		}

		ValidationResult s = super.validateConfig(session, config);
		if (!s.isValid()) {
			errors.addAll(s.getErrors());
		}

		return new ValidationResult(errors);
	}
}
