/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2012, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.keycloak.testsuite.broker;

import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.keycloak.models.RealmModel;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.testsuite.pages.LoginPage;
import org.keycloak.testsuite.rule.KeycloakRule;
import org.keycloak.testsuite.rule.WebResource;
import org.keycloak.testsuite.rule.WebRule;
import org.openqa.selenium.WebDriver;

import java.util.HashMap;

/**
 * @author Pedro Igor
 */
public class AuthenticationBrokerTest {

    @ClassRule
    public static KeycloakRule keycloakRule = new KeycloakRule(new KeycloakRule.KeycloakSetup() {
        @Override
        public void config(RealmManager manager, RealmModel defaultRealm, RealmModel appRealm) {
            appRealm.setSocial(true);
            appRealm.setUpdateProfileOnInitialSocialLogin(false);

            HashMap<String, String> socialConfig = new HashMap<String, String>();
            socialConfig.put("dummy.key", "1234");
            socialConfig.put("dummy.secret", "1234");
            appRealm.setSocialConfig(socialConfig);
        }
    });

    @Rule
    public WebRule webRule = new WebRule(this);
    @WebResource
    protected WebDriver driver;
    @WebResource
    protected LoginPage loginPage;

    @Test
    public void testPostSimpleLoginLogout() {
        loginPage.open();

        loginPage.clickSocial("brokered_idp");

        String pageSource = driver.getPageSource();

        System.out.println(pageSource);
    }
}
