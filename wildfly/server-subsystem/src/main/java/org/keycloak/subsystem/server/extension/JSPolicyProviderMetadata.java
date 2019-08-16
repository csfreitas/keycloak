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

import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.policy.provider.PolicySpi;
import org.keycloak.authorization.policy.provider.js.JSPolicyProviderFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.ScriptModel;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;
import org.keycloak.representations.idm.authorization.AbstractPolicyRepresentation;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;
import org.keycloak.scripting.ScriptingProvider;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class JSPolicyProviderMetadata extends ScriptProviderMetadata {

    JSPolicyProviderMetadata(String name) {
        super(name);
    }

    @Override
    protected Class<? extends Spi> getSpi() {
        return PolicySpi.class;
    }

    @Override
    public ProviderFactory createFactory() {
        String name = getName();

        return new JSPolicyProviderFactory() {
            @Override
            public String getId() {
                return super.getId() + "-" + name;
            }

            @Override
            public String getName() {
                return name;
            }

            @Override
            public boolean isDefault() {
                return true;
            }

            @Override
            public AbstractPolicyRepresentation toRepresentation() {
                PolicyRepresentation representation = new PolicyRepresentation();

                representation.setName(name);
                representation.setType(getId());

                return representation;
            }

            @Override
            protected ScriptModel getScriptModel(Policy policy, RealmModel realm, ScriptingProvider scripting) {
                return scripting.createScript(realm.getId(), ScriptModel.TEXT_JAVASCRIPT, name, getCode(), name);
            }
        };
    }
}
