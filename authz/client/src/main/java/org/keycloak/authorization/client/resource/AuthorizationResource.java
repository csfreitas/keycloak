/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
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
package org.keycloak.authorization.client.resource;


import java.io.IOException;
import java.util.function.Supplier;

import org.keycloak.authorization.client.AuthorizationDeniedException;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.authorization.client.representation.AuthorizationRequest;
import org.keycloak.authorization.client.representation.AuthorizationResponse;
import org.keycloak.authorization.client.representation.ServerConfiguration;
import org.keycloak.authorization.client.util.Http;
import org.keycloak.authorization.client.util.HttpResponseException;
import org.keycloak.util.JsonSerialization;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class AuthorizationResource {

    private Configuration configuration;
    private ServerConfiguration serverConfiguration;
    private Http http;
    private Supplier<String> supplier;

    public AuthorizationResource(Configuration configuration, ServerConfiguration serverConfiguration, Http http, Supplier<String> supplier) {
        this.configuration = configuration;
        this.serverConfiguration = serverConfiguration;
        this.http = http;
        this.supplier = supplier;
    }

    public AuthorizationResponse authorize(AuthorizationRequest request) {
        try {
            String claimToken = request.getClaimToken();

            if (claimToken == null && supplier != null) {
                claimToken = supplier.get();
            }

            if (configuration.getAuthorization().isVersion("v1")) {
                return authorizeUsingV1(request, claimToken);
            } else {
                return authorizeUsingV2(request, claimToken);
            }
        } catch (HttpResponseException e) {
            if (403 == e.getStatusCode()) {
                throw new AuthorizationDeniedException(e);
            }
            throw new RuntimeException("Failed to obtain authorization data.", e);
        } catch (Exception e) {
            throw new RuntimeException("Failed to obtain authorization data.", e);
        }
    }

    private AuthorizationResponse authorizeUsingV2(AuthorizationRequest request, String claimToken) {
        return http.<AuthorizationResponse>post(serverConfiguration.getTokenEndpoint())
                .authentication()
                .uma(request.getTicket(), claimToken, request.getClaimTokenFormat(), request.getPct(), request.getRpt(), request.getScope())
                .response()
                .json(AuthorizationResponse.class)
                .execute();
    }

    private AuthorizationResponse authorizeUsingV1(AuthorizationRequest request, String claimToken) {
        try {
            return http.<AuthorizationResponse>post("/authz/authorize")
                    .authorizationBearer(claimToken)
                    .json(JsonSerialization.writeValueAsBytes(request))
                    .response().json(AuthorizationResponse.class).execute();
        } catch (IOException cause) {
            throw new RuntimeException("Failed to obtain RPT", cause);
        }
    }
}
