/*
 * Copyright 2019 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.adapters.authorization;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.OIDCHttpFacade;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.ClientAuthorizationContext;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.adapters.config.PolicyEnforcerConfig;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class AdapterAuthorizationContext extends ClientAuthorizationContext {

    private final PolicyEnforcer customEnforcer;
    private final OIDCHttpFacade httpFacade;

    public AdapterAuthorizationContext(AccessToken authzToken,
            PolicyEnforcerConfig.PathConfig current,
            AuthzClient client, PolicyEnforcer customEnforcer, OIDCHttpFacade httpFacade) {
        super(authzToken, current, client);
        this.customEnforcer = customEnforcer;
        this.httpFacade = httpFacade;
    }

    public void authorize(Map<String, Set<String>> permissionMap) {
        try {
            Map<String, ResourceRepresentation> resolvedMap = resolvePermissionMap(permissionMap);
            customEnforcer.enforce(httpFacade, resolvedMap);
        } catch (Exception ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    public ResourceRepresentation createResource(ResourceRepresentation resource) {
        if (resource.getName() == null || "".equals(resource.getName().trim())) {
            throw new IllegalArgumentException("");
        }
        
        AuthzClient authzclient = getClient();
        String token = authzclient.obtainAccessToken().getToken();
        return authzclient.protection(token).resource().create(resource);
    }

    public void deleteResource(String resourceName) {
        AuthzClient authzclient = getClient();
        String token = authzclient.obtainAccessToken().getToken();
        if (customEnforcer.getPaths().containsKey(resourceName)) {
            String resourceId = customEnforcer.getPaths().get(resourceName).getId();
            authzclient.protection(token).resource().delete(resourceId);
        }
    }

    protected Map<String, ResourceRepresentation> resolvePermissionMap(Map<String, Set<String>> permissionMap) {
        Map<String, ResourceRepresentation> resolvedMap = new HashMap();
        try {
            for (Map.Entry<String, Set<String>> resource : permissionMap.entrySet()) {
                if (customEnforcer.getPathMatcher().matches(resource.getKey()) != null) {
                    PolicyEnforcerConfig.PathConfig pathConfig = customEnforcer.getPathMatcher().matches(resource.getKey());
                    Set<String> requestedScopes =  resource.getValue();
                    if(pathConfig.getScopes().containsAll(requestedScopes)) {
                        ResourceRepresentation customResource = new ResourceRepresentation(pathConfig.getName());
                        for (String scope : resource.getValue()) {
                            customResource.addScope(scope);
                        }
                        resolvedMap.put(pathConfig.getId(), customResource);
                    }
                    else
                        throw new RuntimeException("Scope specified for resource "+ pathConfig.getPath() + " does not exist");
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return resolvedMap;
    }
}
