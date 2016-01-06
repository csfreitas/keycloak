/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
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
package org.keycloak.services.resources.admin.spi;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.ServerInfoAwareProviderFactory;

/**
 * <p>A factory for {@link RealmAdminResourceProvider}.</p>
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 *
 * @see RealmAdminResourceSPI
 * @see RealmAdminResourceProvider
 */
public interface RealmAdminResourceProviderFactory extends ProviderFactory<RealmAdminResourceProvider>, ServerInfoAwareProviderFactory {

    RealmAdminResourceProvider create(RealmModel realm, KeycloakSession keycloakSession);
}
