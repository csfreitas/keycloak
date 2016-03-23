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

package org.keycloak.adapters.elytron;

import org.jboss.logging.Logger;
import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.AdapterTokenStore;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.NodesRegistrationManagement;
import org.keycloak.adapters.PreAuthActionsHandler;
import org.keycloak.adapters.RequestAuthenticator;
import org.keycloak.adapters.spi.AuthChallenge;
import org.keycloak.adapters.spi.AuthOutcome;
import org.keycloak.adapters.spi.UserSessionManagement;
import org.keycloak.enums.TokenStore;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.HttpServerSession;

import javax.security.auth.callback.CallbackHandler;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
class KeycloakHttpServerAuthenticationMechanism implements HttpServerAuthenticationMechanism {

    static Logger log = Logger.getLogger(KeycloakHttpServerAuthenticationMechanismFactory.class);
    static final String NAME = "KEYCLOAK";

    private final Map<String, ?> properties;
    private final CallbackHandler callbackHandler;
    private final AdapterDeploymentContext deploymentContext;

    public KeycloakHttpServerAuthenticationMechanism(Map<String, ?> properties, CallbackHandler callbackHandler, AdapterDeploymentContext deploymentContext) {
        this.properties = properties;
        this.callbackHandler = callbackHandler;
        this.deploymentContext = deploymentContext;
    }

    @Override
    public String getMechanismName() {
        return NAME;
    }

    @Override
    public void evaluateRequest(HttpServerRequest request) throws HttpAuthenticationException {
        NodesRegistrationManagement nodesRegistrationManagement = new NodesRegistrationManagement();
        final ElytronHttpFacade httpFacade = new ElytronHttpFacade(request);
        KeycloakDeployment deployment = this.deploymentContext.resolveDeployment(httpFacade);

        PreAuthActionsHandler preActions = new PreAuthActionsHandler(new UserSessionManagement() {
            @Override
            public void logoutAll() {
                Set<String> sessions = httpFacade.getSessions();
                logoutHttpSessions(sessions.stream().collect(Collectors.toList()));
            }

            @Override
            public void logoutHttpSessions(List<String> ids) {
                for (String id : ids) {
                    HttpServerSession session = httpFacade.getSession(id);

                    if (session != null) {
                        session.invalidate();
                    }
                }

            }
        }, this.deploymentContext, httpFacade);

        if (preActions.handleRequest()) {
            return;
        }

        if (deployment.isConfigured()) {
            nodesRegistrationManagement.tryRegister(deployment);

            AdapterTokenStore tokenStore = getTokenStore(httpFacade, deployment);
            RequestAuthenticator authenticator = new ElytronRequestAuthenticator(this.callbackHandler, httpFacade, deployment, tokenStore, getConfidentialPort(request));
            AuthOutcome outcome = authenticator.authenticate();

            if (outcome == AuthOutcome.AUTHENTICATED) {
                return;
            }

            AuthChallenge challenge = authenticator.getChallenge();

            if (challenge != null) {
                httpFacade.authenticationInProgress(challenge);
                return;
            }

            if (outcome == AuthOutcome.FAILED) {
                httpFacade.authenticationFailed(challenge);
                return;
            }
        }

        request.noAuthenticationInProgress();
    }

    private AdapterTokenStore getTokenStore(ElytronHttpFacade httpFacade, KeycloakDeployment deployment) {
        if (deployment.getTokenStore() == TokenStore.SESSION) {
            return new ElytronSessionTokenStore(httpFacade, deployment, this.callbackHandler);
        } else {
            return new ElytronCookieTokenStore(httpFacade, deployment, this.callbackHandler);
        }
    }

//    protected void registerNotifications(final SecurityContext securityContext) {
//
//        final NotificationReceiver logoutReceiver = new NotificationReceiver() {
//            @Override
//            public void handleNotification(SecurityNotification notification) {
//                if (notification.getEventType() != SecurityNotification.EventType.LOGGED_OUT) return;
//
//                HttpServerExchange exchange = notification.getExchange();
//                UndertowHttpFacade facade = createFacade();
//                KeycloakDeployment deployment = deploymentContext.resolveDeployment(facade);
//                KeycloakSecurityContext ksc = exchange.getAttachment(OIDCUndertowHttpFacade.KEYCLOAK_SECURITY_CONTEXT_KEY);
//                if (ksc != null && ksc instanceof RefreshableKeycloakSecurityContext) {
//                    ((RefreshableKeycloakSecurityContext) ksc).logout(deployment);
//                }
//                AdapterTokenStore tokenStore = getTokenStore(exchange, facade, deployment, securityContext);
//                tokenStore.logout();
//            }
//        };
//
//        securityContext.registerNotificationReceiver(logoutReceiver);
//    }

    protected int getConfidentialPort(HttpServerRequest request) {
        int confidentialPort = 8443;
//        if (request.getRequestScheme().equalsIgnoreCase("HTTPS")) {
//            confidentialPort = request.getHostPort();
//        } else if (false) {
//            // TODO: obtain confidential port from Elytron
////            confidentialPort = portManager.getConfidentialPort(exchange);
//        }
        return confidentialPort;
    }
}
