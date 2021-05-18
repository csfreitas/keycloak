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

import org.keycloak.validate.validators.NotBlankValidator;

/**
 * Base class for String value format validators. Functionality covered in this base class:
 * <ul>
 * <li>accepts plain string and collections of strings as input
 * <li>each item is validated for collections of strings, see
 * {@link #validateFormat(String, String, ValidationContext, ValidatorConfig)}
 * <li>validation stops after first error for collections
 * <li>null and empty string values are always treated as valid to support optional fields! Use other validators (like
 * {@link NotBlankValidator} to force field as required.
 * </ul>
 * 
 * @author Vlastimil Elias <velias@redhat.com>
 *
 */
public abstract class StringFormatValidatorBase implements SimpleValidator {

	@Override
	public ValidationContext validate(Object input, String inputHint, ValidationContext context, ValidatorConfig config) {

		if (input != null) {
			if (input instanceof String) {
				validateStringValue((String) input, inputHint, context, config);
			} else if (input instanceof Collection) {
				@SuppressWarnings("unchecked")
				Collection<Object> values = (Collection<Object>) input;
				if (!values.isEmpty()) {
					for (Object value : values) {
						if (!(value instanceof String)) {
							context.addError(new ValidationError(getId(), inputHint, ValidationError.MESSAGE_INVALID_VALUE, input));
							return context;
						}
						if (!validateStringValue((String) value, inputHint, context, config)) {
							return context;
						}
					}
				}
			} else {
				context.addError(new ValidationError(getId(), inputHint, ValidationError.MESSAGE_INVALID_VALUE, input));
			}
		}
		return context;
	}

	private boolean validateStringValue(String value, String inputHint, ValidationContext context, ValidatorConfig config) {
		if (value != null && !value.isEmpty())
			return validateFormat(value, inputHint, context, config);
		else
			return true;
	}

	/**
	 * Validate format of the String value. Always use {@link ValidationContext#addError(ValidationError)} to report
	 * error to the user!
	 * 
	 * @param value to be validated, never null nor empty
	 * @param inputHint
	 * @param context for the validation. Add errors into it.
	 * @param config of the validation if provided
	 * @return true if value is valid, false if it is invalid (used to control Collection validation process only, always add
	 *         error into context in this case)
	 */
	protected abstract boolean validateFormat(String value, String inputHint, ValidationContext context, ValidatorConfig config);
}
