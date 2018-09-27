/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.models.cache.infinispan.entities;

import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.models.GroupModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;

import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class CachedUser extends AbstractExtendableRevisioned implements InRealm  {
    private String realm;
    private String username;
    private Long createdTimestamp;
    private String firstName;
    private String lastName;
    private String email;
    private boolean emailVerified;
    private boolean enabled;
    private String federationLink;
    private String serviceAccountClientLink;
    private Function<Supplier<UserModel>, MultivaluedHashMap<String, String>> attributes;
    private Function<Supplier<UserModel>, Set<String>> requiredActions;
    private Function<Supplier<UserModel>, Set<String>> roleMappings;
    private Function<Supplier<UserModel>, Set<String>> groups;
    private int notBefore;



    public CachedUser(Long revision, RealmModel realm, UserModel user, int notBefore) {
        super(revision, user.getId());
        this.realm = realm.getId();
        this.username = user.getUsername();
        this.createdTimestamp = user.getCreatedTimestamp();
        this.firstName = user.getFirstName();
        this.lastName = user.getLastName();
        String id = user.getId();
        this.attributes = new Function<Supplier<UserModel>, MultivaluedHashMap<String, String>>() {
            MultivaluedHashMap<String, String> cached;
            @Override
            public MultivaluedHashMap<String, String> apply(Supplier<UserModel> userModel) {
                if (cached == null) {
                    cached = new MultivaluedHashMap(userModel.get().getAttributes());
                }
                return cached;
            }
        };
        this.email = user.getEmail();
        this.emailVerified = user.isEmailVerified();
        this.enabled = user.isEnabled();
        this.federationLink = user.getFederationLink();
        this.serviceAccountClientLink = user.getServiceAccountClientLink();
        this.requiredActions = new Function<Supplier<UserModel>, Set<String>>() {
            Set<String> cached;
            @Override
            public Set<String> apply(Supplier<UserModel> userModel) {
                if (cached == null) {
                    cached = new HashSet<>(userModel.get().getRequiredActions());
                }
                return cached;
            }
        };
        this.roleMappings = new Function<Supplier<UserModel>, Set<String>>() {
            Set<String> cached;
            @Override
            public Set<String> apply(Supplier<UserModel> userModel) {
                if (cached == null) {
                    cached = userModel.get().getRoleMappings().stream().map(RoleModel::getId).collect(Collectors.toSet());
                }
                return cached;
            }
        };
        this.groups = new Function<Supplier<UserModel>, Set<String>>() {
            Set<String> cached;
            @Override
            public Set<String> apply(Supplier<UserModel> userModel) {
                if (cached == null) {
                    cached = userModel.get().getGroups().stream().map(GroupModel::getId).collect(Collectors.toSet());
                }
                return cached;
            }
        };
        this.notBefore = notBefore;
    }

    public String getRealm() {
        return realm;
    }

    public String getUsername() {
        return username;
    }

    public Long getCreatedTimestamp() {
        return createdTimestamp;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public String getEmail() {
        return email;
    }

    public boolean isEmailVerified() {
        return emailVerified;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public MultivaluedHashMap<String, String> getAttributes(Supplier<UserModel> userModel) {
        return attributes.apply(userModel);
    }

    public Set<String> getRequiredActions(Supplier<UserModel> userModel) {
        return requiredActions.apply(userModel);
    }

    public Set<String> getRoleMappings(Supplier<UserModel> userModel) {
        return roleMappings.apply(userModel);
    }

    public String getFederationLink() {
        return federationLink;
    }

    public String getServiceAccountClientLink() {
        return serviceAccountClientLink;
    }

    public Set<String> getGroups(Supplier<UserModel> userModel) {
        return groups.apply(userModel);
    }

    public int getNotBefore() {
        return notBefore;
    }
}
