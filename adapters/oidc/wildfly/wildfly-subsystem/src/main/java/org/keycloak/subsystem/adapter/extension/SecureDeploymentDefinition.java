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

/**
 * Defines attributes and operations for a secure-deployment.
 *
 * @author Stan Silvert ssilvert@redhat.com (C) 2013 Red Hat Inc.
 */
final class SecureDeploymentDefinition extends AbstractAdapterConfigurationDefinition {

    static final String TAG_NAME = "secure-deployment";

    public SecureDeploymentDefinition() {
        super(TAG_NAME, ALL_ATTRIBUTES, new SecureDeploymentAddHandler(), new SecureDeploymentRemoveHandler(), new SecureDeploymentWriteAttributeHandler());
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
