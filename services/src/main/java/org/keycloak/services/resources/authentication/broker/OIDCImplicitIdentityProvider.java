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

import org.codehaus.jackson.JsonNode;
import org.keycloak.services.resources.authentication.broker.AuthenticationBrokerService.KeyCloakAuthenticationRequest;
import org.keycloak.social.SocialUser;
import org.keycloak.social.utils.SimpleHttp;
import org.picketlink.identity.federation.web.util.RedirectBindingUtil;
import org.picketlink.json.jose.JWS;
import org.picketlink.json.jose.JWSBuilder;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.net.URI;

/**
 * @author Pedro Igor
 */
public class OIDCImplicitIdentityProvider implements IdentityProvider {

    @Override public String getId() {
        return "oidc_implicit_brokered_idp";
    }

    @Override
    public Response handleRequest(AuthenticationRequest authenticationRequest) {
        KeyCloakAuthenticationRequest keyCloakAuthenticationRequest = (KeyCloakAuthenticationRequest) authenticationRequest;

        try {
            StringBuilder authenticationUrl = new StringBuilder(getAuthorizeEndpoint());
            String redirectUri = UriBuilder.fromUri(keyCloakAuthenticationRequest.getUriInfo().getBaseUri())
                    .path(AuthenticationBrokerService.class)
                    .path(AuthenticationBrokerService.class, "generateAccessTokenGet")
                    .build(keyCloakAuthenticationRequest.getRealm().getName(), "oidc_brokered_idp")
                    .toString();

            authenticationUrl
                    .append("?scope=")
                    .append("openid")
                    .append("&state=").append(RedirectBindingUtil.base64URLEncode(keyCloakAuthenticationRequest.getState().getBytes("UTF-8")))
                    .append("&response_type=").append("token+id_token")
                    .append("&client_id=").append(getClientId())
                    .append("&redirect_uri=").append(redirectUri);

            return Response.temporaryRedirect(URI.create(authenticationUrl.toString())).build();
        } catch (Exception e) {
            throw new RuntimeException("Could not create authentication request.", e);
        }
    }

    private String getAuthorizeEndpoint() {
        return "https://accounts.google.com/o/oauth2/auth";
//        return "https://login.salesforce.com/services/oauth2/authorize";
    }

    private String getClientId() {
        // google
        return "98297877835-mhmadokckidnfpe5j09rsb4f7cqh5h6f.apps.googleusercontent.com";
//        //sales force
//        return "3MVG9fMtCkV6eLhdDoYiojYfhJrWyqLZlXoN02a26Q64I0dFcA2hPD1.8W_qYj8rMjdTysA70pTgLS_d6Up3Z";
    }

    @Override
    public AuthenticationResponse handleResponse(AuthenticationRequest authenticationRequest) {
        KeyCloakAuthenticationRequest keyCloakAuthenticationRequest = (KeyCloakAuthenticationRequest) authenticationRequest;
        UriInfo uriInfo = keyCloakAuthenticationRequest.getUriInfo();

        String state = null;
        SocialUser user = null;

        try {
            String authorizationCode = uriInfo.getQueryParameters().getFirst("code");
            state = uriInfo.getQueryParameters().getFirst("state");

            if (authorizationCode != null) {
                StringBuilder authenticationUrl = new StringBuilder(getTokenEndpoint());
                String redirectUri = UriBuilder.fromUri(keyCloakAuthenticationRequest.getUriInfo().getBaseUri())
                        .path(AuthenticationBrokerService.class)
                        .path(AuthenticationBrokerService.class, "generateAccessTokenGet")
                        .build(keyCloakAuthenticationRequest.getRealm().getName(), getId())
                        .toString();

                authenticationUrl
                        .append("?state=").append(state)
                        .append("&code=").append(authorizationCode)
                        .append("&response_type=").append("token+id_token")
                        .append("&client_id=").append(getClientId())
                        .append("&redirect_uri=").append(redirectUri);

                JsonNode tokens = SimpleHttp.doPost(getTokenEndpoint())
                        .param("code", authorizationCode)
                        .param("client_id", getClientId())
                        .param("client_secret", getClientSecret())
                        .param("redirect_uri", redirectUri)
                        .param("grant_type", "authorization_code").asJson();

                String accessToken = tokens.get("access_token").getTextValue();
                JsonNode idToken = tokens.get("id_token");
                JsonNode keys = SimpleHttp.doGet("https://www.googleapis.com/oauth2/v1/certs").asJson();
                JWS build = new JWSBuilder().build(idToken.getTextValue());
//                JsonNode kid = keys.get(build.getHeader("kid"));
//                String textValue = kid.getTextValue();
//                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
//                Certificate certificate = certificateFactory
//                        .generateCertificate(new ByteArrayInputStream(textValue.getBytes()));
//
//                build = new JWSBuilder().build(idToken.getTextValue(), certificate.getPublicKey().getEncoded());

                user = new SocialUser(build.getSubject(), build.getClaim("email"));

                state = new String(RedirectBindingUtil.urlBase64Decode(uriInfo.getQueryParameters().getFirst("state")));
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Could not process response from identity provider.", e);
        }

        return new AuthenticationBrokerService.KeyCloakAuthenticationResponse(user, state, null);
    }

    private String getTokenEndpoint() {
        return "https://accounts.google.com/o/oauth2/token";
//        return "https://login.salesforce.com/services/oauth2/token";
    }

    private String getClientSecret() {
        //google
        return "QHqvae1ZX1oFu4MgMaH3tyZQ";
//        //salesforce
//        return "1056316566349684236";
    }
}
