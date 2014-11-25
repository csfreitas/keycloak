/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
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
package org.keycloak.services.resources.authentication.broker;

import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.ClientConnection;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.AccountRoles;
import org.keycloak.models.ClientSessionModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SocialLinkModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.services.managers.EventsManager;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.services.resources.flows.Flows;
import org.keycloak.social.SocialUser;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.util.HashMap;
import java.util.Map;

import static org.keycloak.events.Details.AUTH_METHOD;
import static org.keycloak.events.Errors.INVALID_CODE;
import static org.keycloak.events.EventType.LOGIN;
import static org.keycloak.models.ClientSessionModel.Action.AUTHENTICATE;

/**
 * @author Pedro Igor
 */
@Path("/broker")
public class AuthenticationBrokerService {

    @Context
    private UriInfo uriInfo;

    @Context
    private KeycloakSession session;

    @Context
    private ClientConnection clientConnection;

    @Context
    private HttpRequest request;

    private final Map<String, IdentityProvider> providers = new HashMap<String, IdentityProvider>();

    public AuthenticationBrokerService() {
        SamlIdentityProvider samlIdentityProvider = new SamlIdentityProvider();

        providers.put(samlIdentityProvider.getId(), samlIdentityProvider);

        OIDCIdentityProvider oidcIdentityProvider = new OIDCIdentityProvider();

        providers.put(oidcIdentityProvider.getId(), oidcIdentityProvider);

        OIDCImplicitIdentityProvider oidcImplicitIdentityProvider = new OIDCImplicitIdentityProvider();

        providers.put(oidcImplicitIdentityProvider.getId(), oidcImplicitIdentityProvider);

    }

    @GET
    @Path("{realm}/login")
    public Response performLogin(@PathParam("realm") final String realmName,
            @QueryParam("provider_id") final String providerId,
            @QueryParam("code") final String code) {
        RealmManager realmManager = new RealmManager(session);
        RealmModel realm = realmManager.getRealmByName(realmName);
        EventBuilder event = new EventsManager(realm, session, clientConnection).createEventBuilder()
                .event(LOGIN)
                .detail(AUTH_METHOD, "social@" + providerId);

        IdentityProvider identityProvider = getBrokeredIdentityProvider(providerId);

        if (identityProvider == null) {
            return Flows.forms(session, realm, null, uriInfo).setError("Identity Provider not found").createErrorPage();
        }

        ClientSessionCode clientCode = isValidAuthorizationCode(code, realm);

        if (clientCode == null) {
            return handleInvalidAuthorizationCode(realm, event, "Invalid code, please login again through your application.");
        }

        try {
            return identityProvider.handleRequest(
                    new KeyCloakAuthenticationRequest(realm, this.session, clientCode.getClientSession(), this.request,
                            this.uriInfo, code));
        } catch (Exception e) {
            event.error("authentication_broker_failed");
            return Flows.forms(session, realm, null, uriInfo)
                    .setError("Could not send authentication request to identity provider")
                    .createErrorPage();
        }
    }

    @GET
    @Path("{realm}/{provider_id}")
    public Response generateAccessTokenGet(@PathParam("realm") final String realmName,
            @PathParam("provider_id") final String providerId) {
        return generateTokenRequest(realmName, providerId);
    }

    @POST
    @Path("{realm}/{provider_id}")
    public Response generateAccessTokenPost(@PathParam("realm") final String realmName,
            @PathParam("provider_id") final String providerId) {
        return generateTokenRequest(realmName, providerId);
    }

    private Response generateTokenRequest(String realmName, String providerId) {
        RealmManager realmManager = new RealmManager(session);
        RealmModel realm = realmManager.getRealmByName(realmName);
        EventBuilder event = new EventsManager(realm, session, clientConnection).createEventBuilder()
                .event(LOGIN)
                .detail(AUTH_METHOD, "social@");

        try {
            IdentityProvider provider = getBrokeredIdentityProvider(providerId);

            if (provider == null) {
                return Flows.forms(session, realm, null, uriInfo).setError("Social provider not found").createErrorPage();
            }

            KeyCloakAuthenticationResponse authenticationResponse = (KeyCloakAuthenticationResponse) provider
                    .handleResponse(new KeyCloakAuthenticationRequest(realm, this.session, this.request, this.uriInfo));

            Response response = authenticationResponse.getResponse();

            if (response != null) {
                return response;
            }

            SocialUser socialUser = authenticationResponse.getUser();
            String code = authenticationResponse.getState();

            if (code == null) {
                return handleInvalidAuthorizationCode(realm, event, "No authorization code provided.");
            }

            ClientSessionCode clientCode = isValidAuthorizationCode(code, realm);

            if (clientCode == null) {
                return handleInvalidAuthorizationCode(realm, event,
                        "Invalid authorization code, please login again through your application.");
            }

            return performLocalAuthentication(realm, event, provider, socialUser, clientCode);
        } catch (Exception e) {
            if (session.getTransaction().isActive()) {
                session.getTransaction().rollback();
            }
        } finally {
            if (session.getTransaction().isActive()) {
                session.getTransaction().commit();
            }
        }

        return Response.ok().build();
    }

    private Response performLocalAuthentication(RealmModel realm, EventBuilder event, IdentityProvider provider,
            SocialUser socialUser, ClientSessionCode clientCode) {
        event.detail(Details.USERNAME, socialUser.getId() + "@" + provider.getId());

        SocialLinkModel socialLink = new SocialLinkModel(provider.getId(), socialUser.getId(),
                socialUser.getUsername());
        UserModel user = session.users().getUserBySocialLink(socialLink, realm);
        ClientSessionModel clientSession = clientCode.getClientSession();

        // Check if user is already authenticated (this means linking social into existing user account)
        if (clientSession.getUserSession() != null) {

            UserModel authenticatedUser = clientSession.getUserSession().getUser();

            event.event(EventType.SOCIAL_LINK).user(authenticatedUser.getId());

            if (user != null) {
                event.error(Errors.SOCIAL_ID_IN_USE);
                return Flows.forwardToSecurityFailurePage(session, realm, uriInfo,
                        "This social account is already linked to other user");
            }

            if (!authenticatedUser.isEnabled()) {
                event.error(Errors.USER_DISABLED);
                return Flows.forwardToSecurityFailurePage(session, realm, uriInfo, "User is disabled");
            }

            if (!authenticatedUser.hasRole(realm.getApplicationByName(Constants.ACCOUNT_MANAGEMENT_APP).getRole(
                    AccountRoles.MANAGE_ACCOUNT))) {
                event.error(Errors.NOT_ALLOWED);
                return Flows.forwardToSecurityFailurePage(session, realm, uriInfo,
                        "Insufficient permissions to link social account");
            }

            session.users().addSocialLink(realm, authenticatedUser, socialLink);

            event.success();
            return Response.status(302).location(UriBuilder.fromUri(clientSession.getRedirectUri()).build()).build();
        }

        if (user == null) {
            user = session.users().addUser(realm, KeycloakModelUtils.generateId());
            user.setEnabled(true);
            user.setFirstName(socialUser.getFirstName());
            user.setLastName(socialUser.getLastName());
            user.setEmail(socialUser.getEmail());

            if (realm.isUpdateProfileOnInitialSocialLogin()) {
                user.addRequiredAction(UserModel.RequiredAction.UPDATE_PROFILE);
            }

            session.users().addSocialLink(realm, user, socialLink);

            event.clone().user(user).event(EventType.REGISTER)
                    .detail(Details.REGISTER_METHOD, "social@" + provider.getId())
                    .detail(Details.EMAIL, socialUser.getEmail())
                    .removeDetail("auth_method")
                    .success();
        }

        event.user(user);

        if (!user.isEnabled()) {
            event.error(Errors.USER_DISABLED);
            return Flows.forwardToSecurityFailurePage(session, realm, uriInfo, "Your account is not enabled.");
        }

        String username = socialLink.getSocialUserId() + "@" + socialLink.getSocialProvider();

        UserSessionModel userSession = session.sessions()
                .createUserSession(realm, user, username, clientConnection.getRemoteAddr(), "broker", false);
        event.session(userSession);
        TokenManager.attachClientSession(userSession, clientSession);

        AuthenticationManager authManager = new AuthenticationManager();

        return authManager
                .nextActionAfterAuthentication(session, userSession, clientSession, clientConnection, request, uriInfo,
                        event);
    }

    private boolean isSignatureEnabled() {
        return false;
    }

    private ClientSessionCode isValidAuthorizationCode(String code, RealmModel realm) {
        ClientSessionCode clientCode = ClientSessionCode.parse(code, session, realm);

        if (clientCode != null && clientCode.isValid(AUTHENTICATE)) {
            return clientCode;
        }

        return null;
    }

    private Response handleInvalidAuthorizationCode(RealmModel realm, EventBuilder event, String message) {
        event.error(INVALID_CODE);
        return Flows.forwardToSecurityFailurePage(session, realm, uriInfo, message);
    }

    private IdentityProvider getBrokeredIdentityProvider(String providerId) {
        return this.providers.get(providerId);
    }

    static class KeyCloakAuthenticationRequest implements IdentityProvider.AuthenticationRequest {

        private final KeycloakSession keycloakSession;
        private final ClientSessionModel clientSession;
        private final UriInfo uriInfo;
        private final String state;
        private final HttpRequest httpRequest;
        private final RealmModel realm;

        public KeyCloakAuthenticationRequest(RealmModel realm, KeycloakSession keycloakSession, HttpRequest httpRequest,
                UriInfo uriInfo) {
            this(realm, keycloakSession, null, httpRequest, uriInfo, null);
        }

        public KeyCloakAuthenticationRequest(RealmModel realm, KeycloakSession keycloakSession,
                ClientSessionModel clientSession,
                HttpRequest httpRequest, UriInfo uriInfo, String state) {
            this.realm = realm;
            this.keycloakSession = keycloakSession;
            this.clientSession = clientSession;
            this.httpRequest = httpRequest;
            this.uriInfo = uriInfo;
            this.state = state;
        }

        public RealmModel getRealm() {
            return this.realm;
        }

        public KeycloakSession getKeycloakSession() {
            return this.keycloakSession;
        }

        public ClientSessionModel getClientSession() {
            return this.clientSession;
        }

        public UriInfo getUriInfo() {
            return this.uriInfo;
        }

        public String getState() {
            return this.state;
        }

        public HttpRequest getHttpRequest() {
            return this.httpRequest;
        }
    }

    static class KeyCloakAuthenticationResponse implements IdentityProvider.AuthenticationResponse {

        private final Response response;
        private final SocialUser user;
        private final String state;

        public KeyCloakAuthenticationResponse(SocialUser user, String state, Response response) {
            this.user = user;
            this.state = state;
            this.response = response;
        }

        public Response getResponse() {
            return this.response;
        }

        public SocialUser getUser() {
            return this.user;
        }

        public String getState() {
            return this.state;
        }
    }
}
