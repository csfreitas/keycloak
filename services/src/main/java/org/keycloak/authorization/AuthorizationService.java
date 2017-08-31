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

package org.keycloak.authorization;

import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.authorization.authorization.AuthorizationTokenService;
import org.keycloak.authorization.entitlement.EntitlementService;
import org.keycloak.authorization.protection.ProtectionService;

import javax.ws.rs.Path;
import javax.ws.rs.PathParam;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class AuthorizationService {

    private final AuthorizationProvider authorization;

    public AuthorizationService(AuthorizationProvider authorization) {
        this.authorization = authorization;
    }

    @Path("/entitlement")
    public Object getEntitlementService() {
        EntitlementService service = new EntitlementService(this.authorization);

        ResteasyProviderFactory.getInstance().injectProperties(service);

        return service;
    }

    @Path("/protection/{resource_server_id}")
    public Object getProtectionService(@PathParam("resource_server_id") String resourceServerId) {
        ProtectionService service = new ProtectionService(authorization, resourceServerId);

        ResteasyProviderFactory.getInstance().injectProperties(service);

        return service;
    }

    @Path("/authorize")
    public AuthorizationTokenService getTokenService() {
        AuthorizationTokenService resource = new AuthorizationTokenService(this.authorization);

        ResteasyProviderFactory.getInstance().injectProperties(resource);

        return resource;
    }
}
