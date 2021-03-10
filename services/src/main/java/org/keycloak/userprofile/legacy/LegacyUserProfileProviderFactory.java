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

package org.keycloak.userprofile.legacy;

import static org.keycloak.userprofile.legacy.Validators.addBasicValidators;
import static org.keycloak.userprofile.legacy.Validators.addSessionValidators;
import static org.keycloak.userprofile.legacy.Validators.addUserCreationValidators;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.userprofile.ContextKey;
import org.keycloak.userprofile.UserProfile;
import org.keycloak.userprofile.UserProfileProvider;
import org.keycloak.userprofile.UserProfileProviderFactory;
import org.keycloak.userprofile.validation.AttributeValidator;

/**
 * @author <a href="mailto:markus.till@bosch.io">Markus Till</a>
 */
public class LegacyUserProfileProviderFactory implements UserProfileProviderFactory {

    private Map<ContextKey, Function<KeycloakSession, List<AttributeValidator>>> validators = new HashMap<>();

    @Override
    public UserProfileProvider create(KeycloakSession session) {
        return new LegacyUserProfileProvider(session, validators);
    }

    @Override
    public void init(Config.Scope config) {
        configureValidators();
    }

    private void configureValidators() {
        validators.put(UserProfile.DefaultContextKey.IDP_REVIEW,
                session -> {
                    RealmModel realm = session.getContext().getRealm();
                    List<AttributeValidator> validators = new ArrayList<>(addBasicValidators(!realm.isRegistrationEmailAsUsername()));

                    return validators;
                });

        Function<KeycloakSession, List<AttributeValidator>> common = session -> {
            RealmModel realm = session.getContext().getRealm();
            List<AttributeValidator> validators = new ArrayList<>();

            validators.addAll(addBasicValidators(!realm.isRegistrationEmailAsUsername() && realm.isEditUsernameAllowed()));
            validators.addAll(addSessionValidators(session));

            return validators;
        };

        validators.put(UserProfile.DefaultContextKey.ACCOUNT, common);
        validators.put(UserProfile.DefaultContextKey.REGISTRATION_PROFILE, common);
        validators.put(UserProfile.DefaultContextKey.UPDATE_PROFILE, common);

        validators.put(UserProfile.DefaultContextKey.REGISTRATION_USER_CREATION,
                session -> {
                    RealmModel realm = session.getContext().getRealm();
                    List<AttributeValidator> validators = new ArrayList<>(addUserCreationValidators(session));

                    return validators;
                });
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {

    }
    public static final String PROVIDER_ID = "legacy-user-profile";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }


}
