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

package org.keycloak.testsuite;

import org.keycloak.Config;
import org.keycloak.common.util.Resteasy;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.platform.PlatformProvider;
import org.keycloak.services.managers.ApplianceBootstrap;
import org.keycloak.services.resources.KeycloakApplication;

import javax.servlet.ServletContext;

public class TestPlatform implements PlatformProvider {

    @Override
    public void onStartup(Runnable startupHook) {
        KeycloakApplication keycloakApplication = Resteasy.getContextData(KeycloakApplication.class);
        ServletContext context = Resteasy.getContextData(ServletContext.class);
        context.setAttribute(KeycloakSessionFactory.class.getName(),  keycloakApplication.getSessionFactory());
        startupHook.run();
        setupDevConfig(keycloakApplication.getSessionFactory());
    }

    @Override
    public void onShutdown(Runnable shutdownHook) {
    }

    @Override
    public void exit(Throwable cause) {
        throw new RuntimeException(cause);
    }

    protected void setupDevConfig(KeycloakSessionFactory sessionFactory) {
        if (System.getProperty("keycloak.createAdminUser", "true").equals("true")) {
            KeycloakSession session = sessionFactory.create();
            try {
                session.getTransactionManager().begin();
                ApplianceBootstrap applianceBootstrap = new ApplianceBootstrap(session);

                if (session.realms().getRealm(Config.getAdminRealm()) == null) {
                    applianceBootstrap.createMasterRealm();
                }
                if (new ApplianceBootstrap(session).isNoMasterUser()) {
                    new ApplianceBootstrap(session).createMasterRealmUser("admin", "admin");
                }
                session.getTransactionManager().commit();
            } finally {
                session.close();
            }
        }
    }
}
