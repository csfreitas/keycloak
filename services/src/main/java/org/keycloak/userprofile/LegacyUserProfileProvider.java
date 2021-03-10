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

import java.util.Map;
import java.util.regex.Pattern;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * @author <a href="mailto:markus.till@bosch.io">Markus Till</a>
 */
public class LegacyUserProfileProvider implements UserProfileProvider {

    private final KeycloakSession session;
    private final Pattern readOnlyAttributes;
    private final Pattern adminReadOnlyAttributes;

    public LegacyUserProfileProvider(KeycloakSession session, Pattern readOnlyAttributes, Pattern adminReadOnlyAttributes) {
        this.session = session;
        this.readOnlyAttributes = readOnlyAttributes;
        this.adminReadOnlyAttributes = adminReadOnlyAttributes;
    }

    @Override
    public void close() {

    }

    @Override
    public UserProfile create(String name, Map<String, ?> attributes, UserModel user) {
        UserProfile.DefaultContextKey context = UserProfile.DefaultContextKey.valueOf(name);
        DefaultAttributes profileAttributes = new DefaultAttributes(context, attributes, user, adminReadOnlyAttributes, readOnlyAttributes, session);
        return new LegacyUserProfile(context, profileAttributes, user, session, adminReadOnlyAttributes, readOnlyAttributes);
    }

    @Override
    public UserProfile create(String contextKey, Map<String, ?> attributes) {
        return create(contextKey, attributes, null);
    }
}