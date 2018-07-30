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

package org.keycloak.authorization.util;

import java.util.*;
import java.util.stream.Collectors;

import javax.ws.rs.core.Response.Status;

import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.Decision.Effect;
import org.keycloak.authorization.identity.Identity;
import org.keycloak.authorization.model.PermissionTicket;
import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.model.Scope;
import org.keycloak.authorization.permission.ResourcePermission;
import org.keycloak.authorization.policy.evaluation.Result;
import org.keycloak.authorization.store.ResourceStore;
import org.keycloak.authorization.store.ScopeStore;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.representations.idm.authorization.AuthorizationRequest.Metadata;
import org.keycloak.representations.idm.authorization.Permission;
import org.keycloak.services.ErrorResponseException;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public final class Permissions {

    public static ResourcePermission permission(ResourceServer server, Resource resource, Scope scope) {
       return new ResourcePermission(resource, new ArrayList<>(Arrays.asList(scope)), server);
    }

    /**
     * Returns a list of permissions for all resources and scopes that belong to the given <code>resourceServer</code> and
     * <code>identity</code>.
     *
     * TODO: review once we support caches
     *
     * @param resourceServer
     * @param identity
     * @param authorization
     * @return
     */
    public static List<ResourcePermission> all(ResourceServer resourceServer, Identity identity, AuthorizationProvider authorization, AuthorizationRequest request) {
        List<ResourcePermission> permissions = new ArrayList<>();
        StoreFactory storeFactory = authorization.getStoreFactory();
        ResourceStore resourceStore = storeFactory.getResourceStore();
        Metadata metadata = request.getMetadata();
        long limit = Long.MAX_VALUE;

        if (metadata != null && metadata.getLimit() != null) {
            limit = metadata.getLimit();
        }

        // obtain all resources where owner is the resource server
        resourceStore.findByOwner(resourceServer.getId(), resourceServer.getId()).stream().limit(limit).forEach(resource -> permissions.add(createResourcePermissionsWithScopes(resource, new LinkedList(resource.getScopes()), authorization, request)));

        // obtain all resources where owner is the current user
        resourceStore.findByOwner(identity.getId(), resourceServer.getId()).stream().limit(limit).forEach(resource -> permissions.add(createResourcePermissionsWithScopes(resource, new LinkedList(resource.getScopes()), authorization, request)));

        // obtain all resources granted to the user via permission tickets (uma)
        List<PermissionTicket> tickets = storeFactory.getPermissionTicketStore().findGranted(identity.getId(), resourceServer.getId());

        if (!tickets.isEmpty()) {
            Map<String, ResourcePermission> userManagedPermissions = new HashMap<>();

            for (PermissionTicket ticket : tickets) {
                ResourcePermission permission = userManagedPermissions.get(ticket.getResource().getId());

                if (permission == null) {
                    userManagedPermissions.put(ticket.getResource().getId(), new ResourcePermission(ticket.getResource(), new ArrayList<>(), resourceServer, request.getClaims()));
                    limit--;
                }

                if (--limit <= 0) {
                    break;
                }
            }

            permissions.addAll(userManagedPermissions.values());
        }

        return permissions;
    }

    public static ResourcePermission createResourcePermissions(Resource resource, Set<String> requestedScopes, AuthorizationProvider authorization, AuthorizationRequest request) {
        String type = resource.getType();
        ResourceServer resourceServer = resource.getResourceServer();
        List<Scope> scopes;

        if (requestedScopes.isEmpty()) {
            scopes = new LinkedList<>(resource.getScopes());
            // check if there is a typed resource whose scopes are inherited by the resource being requested. In this case, we assume that parent resource
            // is owned by the resource server itself
            if (type != null && !resource.getOwner().equals(resourceServer.getId())) {
                StoreFactory storeFactory = authorization.getStoreFactory();
                ResourceStore resourceStore = storeFactory.getResourceStore();
                resourceStore.findByType(type, resourceServer.getId()).forEach(resource1 -> {
                    if (resource1.getOwner().equals(resourceServer.getId())) {
                        for (Scope typeScope : resource1.getScopes()) {
                            if (!scopes.contains(typeScope)) {
                                scopes.add(typeScope);
                            }
                        }
                    }
                });
            }
        } else {
            ScopeStore scopeStore = authorization.getStoreFactory().getScopeStore();
            scopes = requestedScopes.stream().map(scopeName -> {
                Scope byName = scopeStore.findByName(scopeName, resource.getResourceServer().getId());

                if (byName == null) {
                    throw new ErrorResponseException("invalid_scope", "Invalid scope [" + scopeName + "].", Status.BAD_REQUEST);
                }

                return byName;
            }).collect(Collectors.toList());
        }

        return new ResourcePermission(resource, scopes, resource.getResourceServer(), request.getClaims());
    }

    public static ResourcePermission createResourcePermissionsWithScopes(Resource resource, List<Scope> scopes, AuthorizationProvider authorization, AuthorizationRequest request) {
        String type = resource.getType();
        ResourceServer resourceServer = resource.getResourceServer();

        // check if there is a typed resource whose scopes are inherited by the resource being requested. In this case, we assume that parent resource
        // is owned by the resource server itself
        if (type != null && !resource.getOwner().equals(resourceServer.getId())) {
            StoreFactory storeFactory = authorization.getStoreFactory();
            ResourceStore resourceStore = storeFactory.getResourceStore();
            resourceStore.findByType(type, resourceServer.getId()).forEach(resource1 -> {
                if (resource1.getOwner().equals(resourceServer.getId())) {
                    for (Scope typeScope : resource1.getScopes()) {
                        if (!scopes.contains(typeScope)) {
                            scopes.add(typeScope);
                        }
                    }
                }
            });
        }

        return new ResourcePermission(resource, scopes, resource.getResourceServer(), request.getClaims());
    }

    public static List<Permission> permits(List<Result> evaluation, AuthorizationProvider authorizationProvider, ResourceServer resourceServer) {
        return permits(evaluation, null, authorizationProvider, resourceServer);
    }

    public static List<Permission> permits(List<Result> evaluation, Metadata metadata, AuthorizationProvider authorizationProvider, ResourceServer resourceServer) {
        Map<String, Permission> permissions = new LinkedHashMap<>();

        for (Result result : evaluation) {
            Set<Scope> deniedScopes = new HashSet<>();
            Set<Scope> grantedScopes = new HashSet<>();
            boolean resourceDenied = false;
            ResourcePermission permission = result.getPermission();
            Collection<Result.PolicyResult> results = result.getResults();
            List<Result.PolicyResult> userManagedPermissions = new ArrayList<>();
            int deniedCount = results.size();
            Resource resource = permission.getResource();

            for (Result.PolicyResult policyResult : results) {
                Policy policy = policyResult.getPolicy();
                Set<Scope> policyScopes = policy.getScopes();

                if (Effect.PERMIT.equals(policyResult.getStatus())) {
                    if (isScopePermission(policy)) {
                        for (Scope scope : permission.getScopes()) {
                            if (policyScopes.contains(scope)) {
                                // try to grant any scope from a scope-based permission
                                grantedScopes.add(scope);
                            }
                        }
                    } else if (isResourcePermission(policy)) {
                        // we assume that all requested scopes should be granted given that we are processing a resource-based permission.
                        // Later they will be filtered based on any denied scope, if any.
                        // TODO: we could probably provide a configuration option to let users decide whether or not a resource-based permission should grant all scopes associated with the resource.
                        grantedScopes.addAll(permission.getScopes());
                    } if (resource != null && resource.isOwnerManagedAccess() && "uma".equals(policy.getType())) {
                        userManagedPermissions.add(policyResult);
                    }
                    deniedCount--;
                } else {
                    if (isScopePermission(policy)) {
                        // store all scopes associated with the scope-based permission
                        deniedScopes.addAll(policyScopes);
                    } else if (isResourcePermission(policy)) {
                        resourceDenied = true;
                        deniedScopes.addAll(resource.getScopes());
                    }
                }
            }

            // remove any scope denied from the list of granted scopes
            if (!deniedScopes.isEmpty()) {
                grantedScopes.removeAll(deniedScopes);
            }

            for (Result.PolicyResult policyResult : userManagedPermissions) {
                Policy policy = policyResult.getPolicy();

                grantedScopes.addAll(policy.getScopes());

                resourceDenied = false;
            }

            // if there are no policy results is because the permission didn't match any policy.
            // In this case, if results is empty is because we are in permissive mode.
            if (!results.isEmpty()) {
                // update the current permission with the granted scopes
                permission.getScopes().clear();
                permission.getScopes().addAll(grantedScopes);
            }

            if (deniedCount == 0) {
                result.setStatus(Effect.PERMIT);
                grantPermission(authorizationProvider, permissions, permission, resourceServer, metadata);
            } else {
                // if a full deny or resource denied or the requested scopes were denied
                if (deniedCount == results.size() || resourceDenied || (!deniedScopes.isEmpty() && grantedScopes.isEmpty())) {
                    result.setStatus(Effect.DENY);
                } else {
                    result.setStatus(Effect.PERMIT);
                    grantPermission(authorizationProvider, permissions, permission, resourceServer, metadata);
                }
            }
        }

        return permissions.values().stream().collect(Collectors.toList());
    }

    private static boolean isResourcePermission(Policy policy) {
        return "resource".equals(policy.getType());
    }

    private static boolean isScopePermission(Policy policy) {
        return "scope".equals(policy.getType());
    }

    private static void grantPermission(AuthorizationProvider authorizationProvider, Map<String, Permission> permissions, ResourcePermission permission, ResourceServer resourceServer, Metadata metadata) {
        List<Resource> resources = new ArrayList<>();
        Resource resource = permission.getResource();

        if (resource != null) {
            resources.add(resource);
        } else {
            List<Scope> permissionScopes = permission.getScopes();

            if (!permissionScopes.isEmpty()) {
                ResourceStore resourceStore = authorizationProvider.getStoreFactory().getResourceStore();
                resources.addAll(resourceStore.findByScope(permissionScopes.stream().map(Scope::getId).collect(Collectors.toList()), resourceServer.getId()));
            }
        }

        Set<String> scopes = permission.getScopes().stream().map(Scope::getName).collect(Collectors.toSet());

        if (!resources.isEmpty()) {
            for (Resource allowedResource : resources) {
                String resourceId = allowedResource.getId();
                String resourceName = metadata == null || metadata.getIncludeResourceName() ? allowedResource.getName() : null;
                Permission evalPermission = permissions.get(allowedResource.getId());

                if (evalPermission == null) {
                    evalPermission = new Permission(resourceId, resourceName, scopes, permission.getClaims());
                    permissions.put(resourceId, evalPermission);
                }

                if (scopes != null && !scopes.isEmpty()) {
                    Set<String> finalScopes = evalPermission.getScopes();

                    if (finalScopes == null) {
                        finalScopes = new HashSet();
                        evalPermission.setScopes(finalScopes);
                    }

                    finalScopes.addAll(scopes);
                }
            }
        } else {
            Permission scopePermission = new Permission(null, null, scopes, permission.getClaims());
            permissions.put(scopePermission.toString(), scopePermission);
        }
    }
}
