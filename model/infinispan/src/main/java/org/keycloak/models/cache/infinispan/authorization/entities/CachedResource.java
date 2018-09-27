/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.models.cache.infinispan.authorization.entities;

import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.model.Scope;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.models.cache.infinispan.entities.AbstractRevisioned;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class CachedResource extends AbstractRevisioned implements InResourceServer {

    private String resourceServerId;
    private String iconUri;
    private String owner;
    private String type;
    private String name;
    private String displayName;
    private Function<Supplier<Resource>, Set<String>> uris;
    private Function<Supplier<Resource>, Set<String>> scopesIds;
    private boolean ownerManagedAccess;
    private Function<Supplier<Resource>, MultivaluedHashMap<String, String>> attributes;

    public CachedResource(Long revision, Resource resource) {
        super(revision, resource.getId());
        this.name = resource.getName();
        this.displayName = resource.getDisplayName();
        this.type = resource.getType();
        this.owner = resource.getOwner();
        this.iconUri = resource.getIconUri();
        this.resourceServerId = resource.getResourceServer().getId();
        ownerManagedAccess = resource.isOwnerManagedAccess();

        if (resource.isFetched("uris")) {
            Set<String> cached = new HashSet<>(resource.getUris());
            this.uris = supplier -> cached;
        } else {
            this.uris = new Function<Supplier<Resource>, Set<String>>() {
                Set<String> cached;

                @Override
                public Set<String> apply(Supplier<Resource> resource) {
                    if (cached == null) {
                        cached = new HashSet<>(resource.get().getUris());
                    }
                    return cached;
                }
            };
        }

        if (resource.isFetched("scopes")) {
            Set<String> scopes = resource.getScopes().stream().map(Scope::getId).collect(Collectors.toSet());
            this.scopesIds = supplier -> scopes;
        } else {
            this.scopesIds = new Function<Supplier<Resource>, Set<String>>() {
                Set<String> cached;

                @Override
                public Set<String> apply(Supplier<Resource> resource) {
                    if (cached == null) {
                        cached = resource.get().getScopes().stream().map(Scope::getId).collect(Collectors.toSet());
                    }
                    return cached;
                }
            };
        }

        if (resource.isFetched("attributes")) {
            MultivaluedHashMap<String, String> cached = new MultivaluedHashMap<>(resource.getAttributes());
            this.attributes = supplier -> cached;
        } else {
            this.attributes = new Function<Supplier<Resource>, MultivaluedHashMap<String, String>>() {
                MultivaluedHashMap<String, String> cached;

                @Override
                public MultivaluedHashMap<String, String> apply(Supplier<Resource> resource) {
                    if (cached == null) {
                        cached = new MultivaluedHashMap<>(resource.get().getAttributes());
                    }
                    return cached;
                }
            };
        }
    }


    public String getName() {
        return this.name;
    }

    public String getDisplayName() {
        return this.displayName;
    }

    public Set<String> getUris(Supplier<Resource> resource) {
        return this.uris.apply(resource);
    }

    public String getType() {
        return this.type;
    }

    public String getIconUri() {
        return this.iconUri;
    }

    public String getOwner() {
        return this.owner;
    }

    public boolean isOwnerManagedAccess() {
        return ownerManagedAccess;
    }

    public String getResourceServerId() {
        return this.resourceServerId;
    }

    public Set<String> getScopesIds(Supplier<Resource> resource) {
        return this.scopesIds.apply(resource);
    }

    public Map<String, List<String>> getAttributes(Supplier<Resource> resource) {
        return attributes.apply(resource);
    }
}
