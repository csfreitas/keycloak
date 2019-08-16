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

import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public abstract class ScriptProviderMetadata {

    private final String name;
    private StringBuilder code;

    ScriptProviderMetadata(String name) {
        this.name = name;
    }

    public void setCode(String code) {
        if (this.code == null) {
            this.code = new StringBuilder(code);
        } else {
            this.code.append(code);
        }
    }

    public String getName() {
        return name;
    }

    public String getCode() {
        return code.toString();
    }

    protected abstract Class<? extends Spi> getSpi();
    protected abstract ProviderFactory createFactory();
}
