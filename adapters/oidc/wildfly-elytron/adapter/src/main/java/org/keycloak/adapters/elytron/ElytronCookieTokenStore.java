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
import org.keycloak.KeycloakPrincipal;
import org.keycloak.adapters.AdapterTokenStore;
import org.keycloak.adapters.CookieTokenStore;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.OidcKeycloakAccount;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.RequestAuthenticator;
import org.wildfly.security.auth.server.SecurityIdentity;

import javax.security.auth.callback.CallbackHandler;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ElytronCookieTokenStore implements AdapterTokenStore {

    protected static Logger log = Logger.getLogger(ElytronCookieTokenStore.class);

    private final ElytronHttpFacade httpFacade;
    private final CallbackHandler callbackHandler;

    public ElytronCookieTokenStore(ElytronHttpFacade httpFacade, CallbackHandler callbackHandler) {
        this.httpFacade = httpFacade;
        this.callbackHandler = callbackHandler;
    }

    @Override
    public void checkCurrentToken() {
        // no-op on undertow
    }

    @Override
    public boolean isCached(RequestAuthenticator authenticator) {
        KeycloakDeployment deployment = this.httpFacade.getDeployment();
        KeycloakPrincipal<RefreshableKeycloakSecurityContext> principal = CookieTokenStore.getPrincipalFromCookie(deployment, httpFacade, this);

        if (principal == null) {
            log.debug("Account was not in cookie or was invalid, returning null");
            return false;
        }


        if (!deployment.getRealm().equals(principal.getKeycloakSecurityContext().getRealm())) {
            log.debug("Account in session belongs to a different realm than for this request.");
            return false;
        }

        if (principal.getKeycloakSecurityContext().isActive()) {
            SecurityIdentity securityIdentity = SecurityIdentityUtil.authorize(this.callbackHandler, principal.getKeycloakSecurityContext().getTokenString());

            if (securityIdentity != null) {
                getElytronHttpFacade().authenticationComplete(new ElytronAccount(principal), true);
                return true;
            }
        }

        log.debug("Account was not active, removing cookie and returning false");

        logout();

        return false;
    }

    private ElytronHttpFacade getElytronHttpFacade() {
        return (ElytronHttpFacade) this.httpFacade;
    }

    @Override
    public void saveAccountInfo(OidcKeycloakAccount account) {
        RefreshableKeycloakSecurityContext secContext = (RefreshableKeycloakSecurityContext)account.getKeycloakSecurityContext();
        CookieTokenStore.setTokenCookie(this.httpFacade.getDeployment(), this.httpFacade, secContext);
    }

    @Override
    public void logout() {
        KeycloakPrincipal<RefreshableKeycloakSecurityContext> principal = CookieTokenStore.getPrincipalFromCookie(this.httpFacade.getDeployment(), this.httpFacade, this);

        if (principal == null) {
            return;
        }

        CookieTokenStore.removeCookie(this.httpFacade);
    }

    @Override
    public void refreshCallback(RefreshableKeycloakSecurityContext securityContext) {
        CookieTokenStore.setTokenCookie(this.httpFacade.getDeployment(), httpFacade, securityContext);
    }

    @Override
    public void saveRequest() {

    }

    @Override
    public boolean restoreRequest() {
        return false;
    }
}
