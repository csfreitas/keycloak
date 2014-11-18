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
import org.keycloak.social.AuthCallback;
import org.keycloak.social.AuthRequest;
import org.keycloak.social.SocialAccessDeniedException;
import org.keycloak.social.SocialProvider;
import org.keycloak.social.SocialProviderConfig;
import org.keycloak.social.SocialProviderException;
import org.keycloak.social.SocialUser;
import org.picketlink.common.constants.JBossSAMLURIConstants;
import org.picketlink.identity.federation.api.saml.v2.request.SAML2Request;
import org.picketlink.identity.federation.core.saml.v2.common.IDGenerator;
import org.picketlink.identity.federation.core.saml.v2.util.DocumentUtil;
import org.picketlink.identity.federation.saml.v2.protocol.AuthnRequestType;
import org.picketlink.identity.federation.saml.v2.protocol.ResponseType;
import org.picketlink.identity.federation.web.util.PostBindingUtil;
import org.picketlink.identity.federation.web.util.RedirectBindingUtil;
import org.w3c.dom.Document;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.net.URI;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.List;

import static org.keycloak.events.Details.AUTH_METHOD;
import static org.keycloak.events.Errors.*;
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

    @GET
    @Path("{realm}/authenticate")
    public Response authenticate(@PathParam("realm") final String realmName,
            @QueryParam("provider_id") final String providerId,
            @QueryParam("code") String code) {
        RealmManager realmManager = new RealmManager(session);
        RealmModel realm = realmManager.getRealmByName(realmName);
        EventBuilder event = new EventsManager(realm, session, clientConnection).createEventBuilder()
                .event(LOGIN)
                .detail(AUTH_METHOD, "social@" + providerId);

        SocialProvider provider = getBrokeredIdentityProvider();

        if (provider == null) {
            event.error(SOCIAL_PROVIDER_NOT_FOUND);
            return Flows.forms(session, realm, null, uriInfo).setError("Social provider not found").createErrorPage();
        }

        if (isValidAuthorizationCode(code, realm)) {
            return handleInvalidAuthorizationCode(realm, event, "Invalid code, please login again through your application.");
        }

        try {
            SAML2Request samlRequest = new SAML2Request();
            String id = IDGenerator.create("ID_");

            String assertionConsumerURL = UriBuilder.fromUri(uriInfo.getBaseUri())
                    .path(getClass())
                    .path(getClass(), "generateAccessTokenGet")
                    .build(realmName).toString();

            samlRequest.setNameIDFormat(JBossSAMLURIConstants.NAMEID_FORMAT_EMAIL.get());

            AuthnRequestType authn = samlRequest
                    .createAuthnRequestType(id, assertionConsumerURL, assertionConsumerURL, assertionConsumerURL);
            String binding = JBossSAMLURIConstants.SAML_HTTP_REDIRECT_BINDING.get();

            authn.setProtocolBinding(URI.create(binding));

            StringBuilder authenticationUrl = new StringBuilder("http://localhost:8080/idp/");

            //TODO: this must be obtained from the provider config
            if (isSignatureEnabled()) {
                //TODO: support signed authn requests
            } else {
                Document authnDoc = samlRequest.convert(authn);
                byte[] responseBytes = DocumentUtil.getDocumentAsString(authnDoc).getBytes("UTF-8");
                String urlEncodedResponse = RedirectBindingUtil.deflateBase64URLEncode(responseBytes);
                ClientSessionCode clientCode = ClientSessionCode.parse(code, session, realm);

                authenticationUrl
                        .append("?SAMLRequest=").append(urlEncodedResponse)
                        .append("&RelayState=").append(
                        RedirectBindingUtil.base64URLEncode(("" + code + "&" + providerId).getBytes()));
            }

            return Response.temporaryRedirect(URI.create(authenticationUrl.toString())).build();
        } catch (Exception e) {
            e.printStackTrace();
        }

        event.error("authentication_broker_failed");

        return Flows.forms(session, realm, null, uriInfo).setError("Could not send authentication request to identity provider").createErrorPage();
    }

    @GET
    @Path("{realm}/token")
    public Response generateAccessTokenGet(@PathParam("realm") final String realmName) {
        return Response.ok().build();
    }

    @POST
    @Path("{realm}/token")
    public Response generateAccessTokenPost(@PathParam("realm") final String realmName) {
        RealmManager realmManager = new RealmManager(session);
        RealmModel realm = realmManager.getRealmByName(realmName);
        EventBuilder event = new EventsManager(realm, session, clientConnection).createEventBuilder()
                .event(LOGIN)
                .detail(AUTH_METHOD, "social@");
        List<String> samlResponse = request.getFormParameters().get("SAMLResponse");
        List<String> relayState = request.getFormParameters().get("RelayState");

        if (samlResponse.isEmpty()) {
            return Flows.forms(session, realm, null, uriInfo).setError("No response from identity provider.").createErrorPage();
        }

        if (relayState.isEmpty()) {
            return Flows.forms(session, realm, null, uriInfo).setError("Could not restore authentication state.").createErrorPage();
        }

        try {
            ResponseType samlObject = (ResponseType) new SAML2Request()
                    .getSAML2ObjectFromStream(PostBindingUtil.base64DecodeAsStream(URLDecoder.decode(samlResponse.get(0), "UTF-8")));
            String[] relayStateInfo = new String(RedirectBindingUtil.urlBase64Decode(relayState.get(0))).split("&");
            String code = relayStateInfo[0];
            String providerId = relayStateInfo[1];

            SocialProvider provider = getBrokeredIdentityProvider();

            if (provider == null) {
                return Flows.forms(session, realm, null, uriInfo).setError("Social provider not found").createErrorPage();
            }

            if (isValidAuthorizationCode(code, realm)) {
                return handleInvalidAuthorizationCode(realm, event, "Invalid code, please login again through your application.");
            }

            ClientSessionCode clientCode = ClientSessionCode.parse(code, session, realm);
            ClientSessionModel clientSession = clientCode.getClientSession();
            SocialUser socialUser;
            try {
                HashMap<String, String[]> queryParams = new HashMap<String, String[]>();

                queryParams.put("SAMLResponse", new String[] {samlResponse.get(0)});
                queryParams.put("RelayState", new String[] {relayState.get(0)});

                socialUser = provider.processCallback(clientSession, null, new AuthCallback(queryParams));
            } catch (SocialAccessDeniedException e) {
                event.error(Errors.REJECTED_BY_USER);
                clientSession.setAction(ClientSessionModel.Action.AUTHENTICATE);
                return  Flows.forms(session, realm, clientSession.getClient(), uriInfo).setClientSessionCode(clientCode.getCode()).setWarning(
                        "Access denied").createLogin();
            } catch (SocialProviderException e) {
                return Flows.forwardToSecurityFailurePage(session, realm, uriInfo, "Failed to process social callback");
            }

            event.detail(Details.USERNAME, socialUser.getId() + "@" + provider.getId());

            SocialLinkModel socialLink = new SocialLinkModel(provider.getId(), socialUser.getId(),
                    socialUser.getUsername());
            UserModel user = session.users().getUserBySocialLink(socialLink, realm);

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
            Response response = authManager
                    .nextActionAfterAuthentication(session, userSession, clientSession, clientConnection, request, uriInfo,
                            event);
            if (session.getTransaction().isActive()) {
                session.getTransaction().commit();
            }
            return response;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return Response.ok().build();
    }

    private boolean isSignatureEnabled() {
        return false;
    }

    private boolean isValidAuthorizationCode(String code, RealmModel realm) {
        ClientSessionCode clientCode = ClientSessionCode.parse(code, session, realm);

        return clientCode == null || !clientCode.isValid(AUTHENTICATE);
    }

    private Response handleInvalidAuthorizationCode(RealmModel realm, EventBuilder event, String message) {
        event.error(INVALID_CODE);
        return Flows.forwardToSecurityFailurePage(session, realm, uriInfo, message);
    }

    private SocialProvider getBrokeredIdentityProvider() {
        return new SocialProvider() {
            @Override public String getId() {
                return "brokered_idp";
            }

            @Override public AuthRequest getAuthUrl(ClientSessionModel clientSession, SocialProviderConfig config, String state)
                    throws SocialProviderException {
                return AuthRequest.create("http://localhost:8080/idp/").build();
            }

            @Override public String getName() {
                return "brokered_idp";
            }

            @Override public SocialUser processCallback(ClientSessionModel clientSession, SocialProviderConfig config,
                    AuthCallback callback) throws SocialProviderException {
                try {
                    ResponseType samlObject = (ResponseType) new SAML2Request()
                            .getSAML2ObjectFromStream(PostBindingUtil
                                    .base64DecodeAsStream(URLDecoder.decode(callback.getQueryParam("SAMLResponse"), "UTF-8")));
                    String[] relayStateInfo = new String(RedirectBindingUtil.urlBase64Decode(callback.getQueryParam("RelayState"))).split("&");
                    String code = relayStateInfo[0];
                    String providerId = relayStateInfo[1];

                    return new SocialUser("id", "tomcat");
                } catch (Exception e) {
                    e.printStackTrace();;
                }

                return null;
            }
        };
    }
}
