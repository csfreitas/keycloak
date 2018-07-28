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

package org.keycloak.authorization.policy.evaluation;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.Decision;
import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.model.Scope;
import org.keycloak.authorization.permission.ResourcePermission;
import org.keycloak.authorization.policy.provider.PolicyProvider;
import org.keycloak.authorization.store.PolicyStore;
import org.keycloak.authorization.store.ResourceStore;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.representations.idm.authorization.PolicyEnforcementMode;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class DefaultPolicyEvaluator implements PolicyEvaluator {

    private final AuthorizationProvider authorization;
    private final StoreFactory storeFactory;
    private final PolicyStore policyStore;
    private final ResourceStore resourceStore;

    public DefaultPolicyEvaluator(AuthorizationProvider authorization) {
        this.authorization = authorization;
        storeFactory = this.authorization.getStoreFactory();
        policyStore = storeFactory.getPolicyStore();
        resourceStore = storeFactory.getResourceStore();
    }

    @Override
    public void evaluate(ResourcePermission permission, EvaluationContext executionContext, Decision decision) {
        ResourceServer resourceServer = permission.getResourceServer();
        PolicyEnforcementMode enforcementMode = resourceServer.getPolicyEnforcementMode();

        if (PolicyEnforcementMode.DISABLED.equals(enforcementMode)) {
            new DefaultEvaluation(permission, executionContext, null, decision, authorization).grant();
            return;
        }

        Resource resource = permission.getResource();
        List<Scope> scopes = permission.getScopes();
        AtomicBoolean verified = new AtomicBoolean();

        if (resource != null) {
            verified.compareAndSet(false, evaluatePolicies(() -> policyStore.findByResource(resource.getId(), resourceServer.getId()), permission, executionContext, decision));

            if (resource.getType() != null) {
                verified.compareAndSet(false, evaluatePolicies(() -> {
                    List<Policy> policies = policyStore.findByResourceType(resource.getType(), resourceServer.getId());

                    if (!resource.getOwner().equals(resourceServer.getId())) {
                        for (Resource typedResource : resourceStore.findByType(resource.getType(), resourceServer.getId())) {
                            policies.addAll(policyStore.findByResource(typedResource.getId(), resourceServer.getId()));
                        }
                    }

                    return policies;
                }, permission, executionContext, decision));
            }
        }

        if (!scopes.isEmpty()) {
            verified.compareAndSet(false, evaluatePolicies(() -> policyStore.findByScopeIds(scopes.stream().map(Scope::getId).collect(Collectors.toList()), null, resourceServer.getId()).stream().filter(policy -> policy.getResources().isEmpty()).collect(Collectors.toList()), permission, executionContext, decision));
        }

        if (verified.get()) {
            return;
        }

        if (PolicyEnforcementMode.PERMISSIVE.equals(enforcementMode)) {
            new DefaultEvaluation(permission, executionContext, null, decision, authorization).grant();
        }
    }

    private boolean evaluatePolicies(Supplier<List<Policy>> supplier, ResourcePermission permission, EvaluationContext executionContext, Decision decision) {
        List<Policy> policies = supplier.get();

        if (policies.isEmpty()) {
            return false;
        }

        for (Policy parentPolicy : policies) {
            PolicyProvider policyProvider = authorization.getProvider(parentPolicy.getType());

            if (policyProvider == null) {
                throw new RuntimeException("Unknown parentPolicy provider for type [" + parentPolicy.getType() + "].");
            }

            policyProvider.evaluate(new DefaultEvaluation(permission, executionContext, parentPolicy, decision, authorization));
        }

        return true;
    }
}
