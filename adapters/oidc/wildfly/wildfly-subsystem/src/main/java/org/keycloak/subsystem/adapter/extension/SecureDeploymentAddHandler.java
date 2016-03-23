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

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.AttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.PathAddress;
import org.jboss.as.controller.capability.RuntimeCapability;
import org.jboss.dmr.ModelNode;
import org.jboss.msc.service.ServiceController.Mode;
import org.jboss.msc.service.ServiceName;
import org.wildfly.security.auth.server.HttpAuthenticationFactory;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.*;

/**
 * Add a deployment to a realm.
 *
 * @author Stan Silvert ssilvert@redhat.com (C) 2013 Red Hat Inc.
 */
public final class SecureDeploymentAddHandler extends AbstractAddStepHandler {

    static final String HTTP_SERVER_AUTHENTICATION_CAPABILITY = "org.wildfly.security.http-server-mechanism-factory";
    static final RuntimeCapability<Void> HTTP_SERVER_AUTHENTICATION_RUNTIME_CAPABILITY = RuntimeCapability
            .Builder.of(HTTP_SERVER_AUTHENTICATION_CAPABILITY, true, HttpServerAuthenticationMechanismFactory.class)
            .build();

    public static SecureDeploymentAddHandler INSTANCE = new SecureDeploymentAddHandler();

    private SecureDeploymentAddHandler() {
        super(HTTP_SERVER_AUTHENTICATION_RUNTIME_CAPABILITY);
    }

    @Override
    protected void populateModel(ModelNode operation, ModelNode model) throws OperationFailedException {
        // TODO: localize exception. get id number
        if (!operation.get(OP).asString().equals(ADD)) {
            throw new OperationFailedException("Unexpected operation for add secure deployment. operation=" + operation.toString());
        }

        for (AttributeDefinition attr : SecureDeploymentDefinition.ALL_ATTRIBUTES) {
            attr.validateAndSet(operation, model);
        }
    }

    @Override
    protected void performRuntime(OperationContext context, ModelNode operation, ModelNode model) throws OperationFailedException {
        PathAddress pathAddress = PathAddress.pathAddress(operation.get(OP_ADDR));
        String factoryName = pathAddress.getLastElement().getValue();
        ServiceName serviceName = context.getCapabilityServiceName(HTTP_SERVER_AUTHENTICATION_CAPABILITY, factoryName, HttpServerAuthenticationMechanismFactory.class);
        KeycloakAdapterConfigService ckService = KeycloakAdapterConfigService.getInstance();

        ckService.addSecureDeployment(operation, context.resolveExpressions(model));

        KeycloakHttpAuthenticationFactoryService service = new KeycloakHttpAuthenticationFactoryService(factoryName);

        context.getServiceTarget().addService(serviceName, service).setInitialMode(Mode.ACTIVE).install();
    }
}
