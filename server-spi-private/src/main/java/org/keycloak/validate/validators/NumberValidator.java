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

import org.keycloak.validate.SimpleValueValidatorBase;
import org.keycloak.validate.ValidationContext;
import org.keycloak.validate.ValidatorConfig;

/**
 * 
 * Validate input being any kind of {@link Number}. Accepts String also if convertible to {@link Double}.
 * 
 * @author Vlastimil Elias <velias@redhat.com>
 */
public class NumberValidator extends SimpleValueValidatorBase {

    public static final String ID = "number";

    public static final String MESSAGE_INVALID_NUMBER = "error-invalid-number";

    public static final NumberValidator INSTANCE = new NumberValidator();

    private NumberValidator() {
    	super(MESSAGE_INVALID_NUMBER);
    }

    @Override
    public String getId() {
        return ID;
    }

	@Override
	protected boolean isSupportedClass(Object value, String inputHint, ValidationContext context, ValidatorConfig config) {
		return (value instanceof Number);
	}

	@Override
	protected Object convertStringValue(String value, String inputHint, ValidationContext context, ValidatorConfig config) {
		try {
           return new Double(value);
        } catch (NumberFormatException nfe) {
            return null;
        }
	}

	@Override
	protected boolean validateValue(Object value, String inputHint, ValidationContext context, ValidatorConfig config) {
		// no additional value validations 
		return true;
	}
}
