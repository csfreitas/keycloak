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

package org.keycloak.subsystem.server.extension;

import java.util.HashMap;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorSpi;
import org.keycloak.authentication.authenticators.browser.ScriptBasedAuthenticator;
import org.keycloak.authentication.authenticators.browser.ScriptBasedAuthenticatorFactory;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ScriptAuthenticatorProviderMetadata extends ScriptProviderMetadata {

    ScriptAuthenticatorProviderMetadata(String name) {
        super(name);
    }

    @Override
    protected Class<? extends Spi> getSpi() {
        return AuthenticatorSpi.class;
    }

    @Override
    public ProviderFactory createFactory() {
        AuthenticatorConfigModel model = new AuthenticatorConfigModel();

        model.setConfig(new HashMap<>());
        model.getConfig().put("scriptName", getName());
        model.getConfig().put("scriptCode", getCode().toString());
        model.getConfig().put("scriptDescription", getName());

        return new ScriptBasedAuthenticatorFactory() {
            @Override
            public Authenticator create(KeycloakSession session) {
                return new ScriptBasedAuthenticator() {
                    @Override
                    protected AuthenticatorConfigModel getAuthenticatorConfig(AuthenticationFlowContext context) {
                        return model;
                    }
                };
            }

            @Override
            public String getId() {
                return PROVIDER_ID + "-" + getName();
            }

            @Override
            public boolean isConfigurable() {
                return false;
            }

            @Override
            public boolean isUserSetupAllowed() {
                return false;
            }

            @Override
            public String getDisplayType() {
                return getName();
            }

            @Override
            public String getHelpText() {
                return getName();
            }
        };
    }
}
