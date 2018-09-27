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

import java.util.Collections;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class CachedGroup extends AbstractRevisioned implements InRealm {
    private String realm;
    private String name;
    private String parentId;
    private Function<Supplier<GroupModel>, MultivaluedHashMap<String, String>> attributes;
    private Function<Supplier<GroupModel>, Set<String>> roleMappings;
    private Function<Supplier<GroupModel>, Set<String>> subGroups;

    public CachedGroup(Long revision, RealmModel realm, GroupModel group) {
        super(revision, group.getId());
        this.realm = realm.getId();
        this.name = group.getName();
        this.parentId = group.getParentId();

        this.attributes = new Function<Supplier<GroupModel>, MultivaluedHashMap<String, String>>() {
            MultivaluedHashMap<String, String> cached;
            @Override
            public MultivaluedHashMap<String, String> apply(Supplier<GroupModel> group) {
                if (cached == null) {
                    cached = new MultivaluedHashMap<>(group.get().getAttributes());
                }
                return cached;
            }
        };
        this.roleMappings = new Function<Supplier<GroupModel>, Set<String>>() {
            Set<String> cached;
            @Override
            public Set<String> apply(Supplier<GroupModel> groupModelSupplier) {
                if (cached == null) {
                    cached = groupModelSupplier.get().getRoleMappings().stream().map(RoleModel::getId).collect(Collectors.toSet());
                }
                return cached;
            }
        };
        this.subGroups = new Function<Supplier<GroupModel>, Set<String>>() {
            Set<String> cached;
            @Override
            public Set<String> apply(Supplier<GroupModel> groupModelSupplier) {
                if (cached == null) {
                    cached = groupModelSupplier.get().getSubGroups().stream().map(GroupModel::getId).collect(Collectors.toSet());
                }
                return cached;
            }
        };
    }

    public String getRealm() {
        return realm;
    }

    public MultivaluedHashMap<String, String> getAttributes(Supplier<GroupModel> group) {
        return attributes.apply(group);
    }

    public Set<String> getRoleMappings(Supplier<GroupModel> group) {
        // it may happen that groups were not loaded before so we don't actually need to invalidate entries in the cache
        if (group == null) {
            return Collections.emptySet();
        }
        return roleMappings.apply(group);
    }

    public String getName() {
        return name;
    }

    public String getParentId() {
        return parentId;
    }

    public Set<String> getSubGroups(Supplier<GroupModel> group) {
        return subGroups.apply(group);
    }
}
