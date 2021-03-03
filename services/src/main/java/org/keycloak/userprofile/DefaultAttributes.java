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

import org.keycloak.models.UserModel;
import org.keycloak.userprofile.validation.AttributeValidator;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class DefaultAttributes extends HashMap<String, List<String>> implements UserProfile.Attributes {

    private final UserModel user;
    private final UserProfile profile;
    private final Pattern adminReadOnlyAttributes;
    private final Pattern readOnlyAttributes;
    private Map<String, List<AttributeValidator>> validators = new HashMap<>();

    public DefaultAttributes(UserModel user, UserProfile profile, Pattern adminReadOnlyAttributes,
            Pattern readOnlyAttributes) {
        super(user == null ? Collections.emptyMap() : user.getAttributes());
        this.user = user;
        this.profile = profile;
        this.adminReadOnlyAttributes = adminReadOnlyAttributes;
        this.readOnlyAttributes = readOnlyAttributes;
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
    public boolean validate(String key, List<String> value, Consumer<String> error) {
        boolean status = true;
        List<AttributeValidator> validators = this.validators.getOrDefault(key, Collections.emptyList());

        for (AttributeValidator validator : validators) {
            if (!validator.getValidator().apply(value, profile)) {
                error.accept(validator.getMessage());
                status = false;
            }
        }

        return status;
    }

    void addValidator(String name, String message, BiFunction<List<String>, UserProfile, Boolean> validator) {
        validators.computeIfAbsent(name, s -> new ArrayList<>()).add(new AttributeValidator(message, validator));
    }
}
