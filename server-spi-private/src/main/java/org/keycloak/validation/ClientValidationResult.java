package org.keycloak.validation;

import java.util.Properties;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.keycloak.validate.ValidationError;
import org.keycloak.validate.ValidationResult;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ClientValidationResult {

    private final ValidationResult result;

    public ClientValidationResult(ValidationResult result) {
        this.result = result;
    }

    public String getAllErrorsAsString() {
        return getAllErrorsAsString(ValidationError::getMessage);
    }

    public String getAllLocalizedErrorsAsString(Properties messagesBundle) {
        return getAllErrorsAsString(x -> x.getMessage());
    }

    protected String getAllErrorsAsString(Function<ValidationError, String> function) {
        return result.getErrors().stream().map(function).collect(Collectors.joining("; "));
    }

    public boolean fieldHasError(String fieldId) {
        if (fieldId == null) {
            return false;
        }
        for (ValidationError error : result.getErrors()) {
            if (fieldId.equals(error.getInputHint())) {
                return true;
            }
        }
        return false;
    }
}
