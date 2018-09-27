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

import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.model.Scope;
import org.keycloak.models.cache.infinispan.entities.AbstractRevisioned;
import org.keycloak.representations.idm.authorization.DecisionStrategy;
import org.keycloak.representations.idm.authorization.Logic;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class CachedPolicy extends AbstractRevisioned implements InResourceServer {

    private String type;
    private DecisionStrategy decisionStrategy;
    private Logic logic;
    private String name;
    private String description;
    private String resourceServerId;
    private Function<Supplier<Policy>, Set<String>> associatedPoliciesIds;
    private Function<Supplier<Policy>, Set<String>> resourcesIds;
    private Function<Supplier<Policy>, Set<String>> scopesIds;
    private Function<Supplier<Policy>, Map<String, String>> config;
    private final String owner;

    public CachedPolicy(Long revision, Policy policy) {
        super(revision, policy.getId());
        this.type = policy.getType();
        this.decisionStrategy = policy.getDecisionStrategy();
        this.logic = policy.getLogic();
        this.name = policy.getName();
        this.description = policy.getDescription();
        this.resourceServerId = policy.getResourceServer().getId();

        if (policy.isFetched("associatedPolicies")) {
            Set<String> cached = policy.getAssociatedPolicies().stream().map(Policy::getId).collect(Collectors.toSet());
            this.associatedPoliciesIds = supplier -> cached;
        } else {
            this.associatedPoliciesIds = new Function<Supplier<Policy>, Set<String>>() {
                Set<String> cached;

                @Override
                public Set<String> apply(Supplier<Policy> supplier) {
                    if (cached == null) {
                        cached = supplier.get().getAssociatedPolicies().stream().map(Policy::getId).collect(Collectors.toSet());
                    }
                    return cached;
                }
            };
        }

        if (policy.isFetched("resources")) {
            Set<String> cached = policy.getResources().stream().map(Resource::getId).collect(Collectors.toSet());
            this.resourcesIds = supplier -> cached;
        } else {
            this.resourcesIds = new Function<Supplier<Policy>, Set<String>>() {
                Set<String> cached;

                @Override
                public Set<String> apply(Supplier<Policy> supplier) {
                    if (cached == null) {
                        cached = supplier.get().getResources().stream().map(Resource::getId).collect(Collectors.toSet());
                    }
                    return cached;
                }
            };
        }

        if (policy.isFetched("scopes")) {
            Set<String> cached = policy.getScopes().stream().map(Scope::getId).collect(Collectors.toSet());
            this.scopesIds = supplier -> cached;
        } else {
            this.scopesIds = new Function<Supplier<Policy>, Set<String>>() {
                Set<String> cached;

                @Override
                public Set<String> apply(Supplier<Policy> supplier) {
                    if (cached == null) {
                        cached = supplier.get().getScopes().stream().map(Scope::getId).collect(Collectors.toSet());
                    }
                    return cached;
                }
            };
        }

        if (policy.isFetched("config")) {
            Map<String, String> cached = new HashMap<>(policy.getConfig());
            this.config = supplier -> cached;
        } else {
            this.config = new Function<Supplier<Policy>, Map<String, String>>() {
                Map<String, String> cached;

                @Override
                public Map<String, String> apply(Supplier<Policy> supplier) {
                    if (cached == null) {
                        cached = new HashMap<>(supplier.get().getConfig());
                    }
                    return cached;
                }
            };
        }
        this.owner = policy.getOwner();
    }

    public String getType() {
        return this.type;
    }

    public DecisionStrategy getDecisionStrategy() {
        return this.decisionStrategy;
    }

    public Logic getLogic() {
        return this.logic;
    }

    public Map<String, String> getConfig(Supplier<Policy> policy) {
        return this.config.apply(policy);
    }

    public String getName() {
        return this.name;
    }

    public String getDescription() {
        return this.description;
    }

    public Set<String> getAssociatedPoliciesIds(Supplier<Policy> policy) {
        return this.associatedPoliciesIds.apply(policy);
    }

    public Set<String> getResourcesIds(Supplier<Policy> policy) {
        return this.resourcesIds.apply(policy);
    }

    public Set<String> getScopesIds(Supplier<Policy> policy) {
        return this.scopesIds.apply(policy);
    }

    public String getResourceServerId() {
        return this.resourceServerId;
    }

    public String getOwner() {
        return owner;
    }
}
