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
package org.keycloak.services.resources.spi;

import org.keycloak.provider.Provider;

/**
 * <p>A {@link RealmResourceProvider} is responsible to resolve a given path to a JAX-RS resource object. It serves as an
 * extension point in order to plug additional RESTful endpoints (eg.: additional API) to realms and extend Keycloak capabilities.</p>
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface RealmResourceProvider extends Provider {

    /**
     * Resolves the given {@code pathName} to a JAX-RS resource object or null if the path is unknown to this provider.
     *
     * @param pathName A string representing a path
     * @return A JAX-RS resource for the given path or null if the path is unknown.
     */
    Object getResource(String pathName);
}
