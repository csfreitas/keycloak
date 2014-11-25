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
import org.keycloak.models.ClientSessionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.authentication.broker.AuthenticationBrokerService.KeyCloakAuthenticationRequest;
import org.keycloak.services.resources.authentication.broker.AuthenticationBrokerService.KeyCloakAuthenticationResponse;
import org.keycloak.services.resources.flows.Flows;
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

import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.net.URI;
import java.net.URLDecoder;
import java.util.List;

/**
 * @author Pedro Igor
 */
public class SamlIdentityProvider implements IdentityProvider {

    @Override public String getId() {
        return "saml_brokered_idp";
    }

    @Override
    public Response handleRequest(AuthenticationRequest authenticationRequest) {
        KeyCloakAuthenticationRequest keyCloakAuthenticationRequest = (KeyCloakAuthenticationRequest) authenticationRequest;

        try {
            ClientSessionModel clientSession = keyCloakAuthenticationRequest.getClientSession();
            UriInfo uriInfo = keyCloakAuthenticationRequest.getUriInfo();
            String issuerURL = UriBuilder.fromUri(uriInfo.getBaseUri()).build()
                    .toString();
            String assertionConsumerURL = UriBuilder.fromUri(uriInfo.getBaseUri())
                    .path(AuthenticationBrokerService.class)
                    .path(AuthenticationBrokerService.class, "generateAccessTokenGet")
                    .build(clientSession.getRealm().getName(), getId())
                    .toString();
            String destinationUrl = "http://localhost:8080/idp/";

            SAML2Request samlRequest = new SAML2Request();
            String id = IDGenerator.create("ID_");

            samlRequest.setNameIDFormat(JBossSAMLURIConstants.NAMEID_FORMAT_EMAIL.get());

            AuthnRequestType authn = samlRequest
                    .createAuthnRequestType(id, assertionConsumerURL, destinationUrl, issuerURL);
            String binding = JBossSAMLURIConstants.SAML_HTTP_REDIRECT_BINDING.get();

            authn.setProtocolBinding(URI.create(binding));

            //TODO: this must be obtained from the provider config
            if (isSignatureEnabled()) {
                //TODO: support signed authn requests
            } else {
                Document authnDoc = samlRequest.convert(authn);
                byte[] responseBytes = DocumentUtil.getDocumentAsString(authnDoc).getBytes("UTF-8");
                String urlEncodedResponse = RedirectBindingUtil.deflateBase64URLEncode(responseBytes);
                String relayState = RedirectBindingUtil
                        .base64URLEncode((keyCloakAuthenticationRequest.getState()).getBytes());
                StringBuilder redirectUrl = new StringBuilder(destinationUrl);

                redirectUrl
                        .append("?SAMLRequest=").append(urlEncodedResponse)
                        .append("&RelayState=").append(relayState);

                return Response.temporaryRedirect(URI.create(redirectUrl.toString())).build();
            }
        } catch (Exception e) {
            throw new RuntimeException("Could not create authentication request state.", e);
        }

        return null;
    }

    private boolean isSignatureEnabled() {
        return false;
    }

    @Override
    public AuthenticationResponse handleResponse(AuthenticationRequest authenticationRequest) {
        KeyCloakAuthenticationRequest keyCloakAuthenticationRequest = (KeyCloakAuthenticationRequest) authenticationRequest;
        HttpRequest httpRequest = keyCloakAuthenticationRequest.getHttpRequest();

        List<String> samlResponseParameter = httpRequest.getFormParameters().get("SAMLResponse");
        List<String> relayStateParameter = httpRequest.getFormParameters().get("RelayState");
        KeycloakSession keycloakSession = keyCloakAuthenticationRequest.getKeycloakSession();
        RealmModel realm = keyCloakAuthenticationRequest.getRealm();
        UriInfo uriInfo = keyCloakAuthenticationRequest.getUriInfo();
        Response response = null;

        if (samlResponseParameter.isEmpty()) {
            response = Flows.forms(keycloakSession, realm, null, uriInfo).setError("No response from identity provider.")
                    .createErrorPage();
        }

        if (relayStateParameter.isEmpty()) {
            response = Flows.forms(keycloakSession, realm, null, uriInfo).setError("Could not restore authentication state.")
                    .createErrorPage();
        }

        SocialUser user = null;
        String relayState = null;

        if (response == null) {
            try {
                relayState = new String(RedirectBindingUtil.urlBase64Decode(relayStateParameter.get(0)));

                ResponseType samlObject = (ResponseType) new SAML2Request()
                        .getSAML2ObjectFromStream(PostBindingUtil
                                .base64DecodeAsStream(
                                        URLDecoder.decode(samlResponseParameter.get(0), "UTF-8")));

                user = new SocialUser("tomcat", "tomcat");
            } catch (Exception e) {
                response = Flows.forms(keycloakSession, realm, null, uriInfo).setError("Invalid authentication state.")
                        .createErrorPage();
            }
        }

        return new KeyCloakAuthenticationResponse(user, relayState, response);
    }
}
