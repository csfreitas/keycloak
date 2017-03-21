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
package org.keycloak.adapters.elytron;

import java.io.ByteArrayInputStream;
import java.security.Principal;
import java.util.Set;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.AdapterTokenStore;
import org.keycloak.adapters.AdapterUtils;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.OidcKeycloakAccount;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.RequestAuthenticator;
import org.keycloak.adapters.rotation.AdapterRSATokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.BearerTokenEvidence;
import org.wildfly.security.evidence.Evidence;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class KeycloakSecurityRealm implements SecurityRealm {

    private final KeycloakDeployment deployment;

    public KeycloakSecurityRealm(String config) {
        this.deployment = KeycloakDeploymentBuilder.build(new ByteArrayInputStream(config.getBytes()));
    }

    public KeycloakSecurityRealm() {
        this.deployment = null;
    }

    @Override
    public RealmIdentity getRealmIdentity(Principal principal) throws RealmUnavailableException {
        if (principal instanceof KeycloakPrincipal) {
            return createRealmIdentity((KeycloakPrincipal) principal);
        }
        return RealmIdentity.NON_EXISTENT;
    }

    @Override
    public RealmIdentity getRealmIdentity(Evidence evidence) throws RealmUnavailableException {
        if (evidence instanceof BearerTokenEvidence) {
            if (deployment == null) {
                throw new RuntimeException("Deployment not provided");
            }

            try {
                String token = BearerTokenEvidence.class.cast(evidence).getToken();
                AccessToken accessToken = AdapterRSATokenVerifier.verifyToken(token, deployment);
                KeycloakSecurityContext keycloakSecurityContext = new RefreshableKeycloakSecurityContext(deployment, new AdapterTokenStore() {
                    @Override
                    public void checkCurrentToken() {

                    }

                    @Override
                    public boolean isCached(RequestAuthenticator authenticator) {
                        return false;
                    }

                    @Override
                    public void saveAccountInfo(OidcKeycloakAccount account) {

                    }

                    @Override
                    public void logout() {

                    }

                    @Override
                    public void refreshCallback(RefreshableKeycloakSecurityContext securityContext) {

                    }

                    @Override
                    public void saveRequest() {

                    }

                    @Override
                    public boolean restoreRequest() {
                        return false;
                    }
                }, token, accessToken, null, null, null);
                return createRealmIdentity(new KeycloakPrincipal(AdapterUtils.getPrincipalName(deployment, accessToken), keycloakSecurityContext));
            } catch (VerificationException e) {

            }
        }

        return RealmIdentity.NON_EXISTENT;
    }

    private RealmIdentity createRealmIdentity(KeycloakPrincipal principal) {
        return new RealmIdentity() {
            @Override
            public Principal getRealmIdentityPrincipal() {
                return principal;
            }

            @Override
            public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName) throws RealmUnavailableException {
                return SupportLevel.UNSUPPORTED;
            }

            @Override
            public <C extends Credential> C getCredential(Class<C> credentialType) throws RealmUnavailableException {
                return null;
            }

            @Override
            public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
                return SupportLevel.SUPPORTED;
            }

            @Override
            public boolean verifyEvidence(Evidence evidence) throws RealmUnavailableException {
                return principal != null;
            }

            @Override
            public boolean exists() throws RealmUnavailableException {
                return principal != null;
            }

            @Override
            public AuthorizationIdentity getAuthorizationIdentity() throws RealmUnavailableException {
                RefreshableKeycloakSecurityContext securityContext = (RefreshableKeycloakSecurityContext) principal.getKeycloakSecurityContext();
                Attributes attributes = new MapAttributes();

                Set<String> roles = AdapterUtils.getRolesFromSecurityContext(securityContext);

                attributes.addAll(RoleDecoder.KEY_ROLES, roles);
                attributes.addAll("groups", roles);

                return AuthorizationIdentity.basicIdentity(attributes);
            }
        };
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName) throws RealmUnavailableException {
        return SupportLevel.UNSUPPORTED;
    }

    @Override
    public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
        return SupportLevel.POSSIBLY_SUPPORTED;
    }
}
