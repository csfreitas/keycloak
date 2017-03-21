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
package org.keycloak.subsystem.adapter.extension;

import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.dmr.ModelNode;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ValueService;
import org.jboss.msc.value.Value;
import org.keycloak.adapters.elytron.KeycloakSecurityRealm;
import org.wildfly.security.auth.server.SecurityRealm;

/**
 * Defines attributes and operations for a secure-deployment.
 *
 * @author Stan Silvert ssilvert@redhat.com (C) 2013 Red Hat Inc.
 */
final class SecureDeploymentDefinition extends AbstractAdapterConfigurationDefinition {

    static final RuntimeCapability<Void> SECURITY_REALM_RUNTIME_CAPABILITY = RuntimeCapability
            .Builder.of("org.wildfly.security.security-realm", true, SecurityRealm.class)
            .build();

    static final String TAG_NAME = "secure-deployment";

    public SecureDeploymentDefinition() {
        super(TAG_NAME, ALL_ATTRIBUTES, new SecureDeploymentAddHandler(), new SecureDeploymentRemoveHandler(), new SecureDeploymentWriteAttributeHandler(), new RuntimeCapability[] {SECURITY_REALM_RUNTIME_CAPABILITY});
    }

    /**
     * Add a deployment to a realm.
     *
     * @author Stan Silvert ssilvert@redhat.com (C) 2013 Red Hat Inc.
     */
    static final class SecureDeploymentAddHandler extends AbstractAdapterConfigurationAddHandler {
        SecureDeploymentAddHandler() {
            super(ALL_ATTRIBUTES);
        }

        @Override
        protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model) throws OperationFailedException {
            super.performRuntime(context, operation, model);
            final KeycloakAdapterConfigService ckService = KeycloakAdapterConfigService.getInstance();
            final String name = ckService.deploymentNameFromOp(operation);
            context.getServiceTarget().addService(SECURITY_REALM_RUNTIME_CAPABILITY.fromBaseCapability(name).getCapabilityServiceName(), new ValueService<SecurityRealm>(new Value<SecurityRealm>() {
                @Override
                public SecurityRealm getValue() throws IllegalStateException, IllegalArgumentException {
                    return new KeycloakSecurityRealm(ckService.getJSON(name));
                }
            })).setInitialMode(ServiceController.Mode.ACTIVE).install();
        }
    }

    /**
     * Remove a secure-deployment from a realm.
     *
     * @author Stan Silvert ssilvert@redhat.com (C) 2013 Red Hat Inc.
     */
    static final class SecureDeploymentRemoveHandler extends AbstractAdapterConfigurationRemoveHandler {}

    /**
     * Update an attribute on a secure-deployment.
     *
     * @author Stan Silvert ssilvert@redhat.com (C) 2013 Red Hat Inc.
     */
    static final class SecureDeploymentWriteAttributeHandler extends AbstractAdapterConfigurationWriteAttributeHandler {

        SecureDeploymentWriteAttributeHandler() {
            super(ALL_ATTRIBUTES);
        }
    }
}
