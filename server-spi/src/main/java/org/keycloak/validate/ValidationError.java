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

import java.util.Arrays;
import java.util.Objects;

/**
 * Denotes an error found during validation.
 */
public class ValidationError {

    private static final Object[] EMPTY_PARAMETERS = {};

    /**
     * Holds the name of the validator that reported the {@link ValidationError}.
     */
    private final String validatorId;

    /**
     * Holds an inputHint.
     * <p>
     * This could be a attribute name, a nested field path or a logical key.
     */
    private final String inputHint;

    /**
     * Holds the message key for translation.
     */
    private final String message;

    /**
     * Optional parameters for the message translation.
     */
    private final Object[] messageParameters;

    public ValidationError(String validatorId, String inputHint, String message) {
        this(validatorId, inputHint, message, EMPTY_PARAMETERS);
    }

    public ValidationError(String validatorId, String inputHint, String message, Object... messageParameters) {
        this.validatorId = validatorId;
        this.inputHint = inputHint;
        this.message = message;
        this.messageParameters = messageParameters == null ? EMPTY_PARAMETERS : messageParameters.clone();
    }

    public String getValidatorId() {
        return validatorId;
    }

    public String getInputHint() {
        return inputHint;
    }

    public String getMessage() {
        return message;
    }

    public Object[] getMessageParameters() {
        return messageParameters;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ValidationError)) return false;
        ValidationError that = (ValidationError) o;
        return Objects.equals(validatorId, that.validatorId) && Objects.equals(inputHint, that.inputHint) && Objects.equals(message, that.message) && Arrays.equals(messageParameters, that.messageParameters);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(validatorId, inputHint, message);
        result = 31 * result + Arrays.hashCode(messageParameters);
        return result;
    }

    @Override
    public String toString() {
        return "ValidationError{" +
                "validatorId='" + validatorId + '\'' +
                ", inputHint='" + inputHint + '\'' +
                ", message='" + message + '\'' +
                ", messageParameters=" + Arrays.toString(messageParameters) +
                '}';
    }
}