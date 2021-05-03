/*
 *
 *  * Copyright 2021  Red Hat, Inc. and/or its affiliates
 *  * and other contributors as indicated by the @author tags.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  * http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package org.keycloak.testsuite.user.profile;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.testsuite.runonserver.RunOnServer;
import org.keycloak.userprofile.UserProfile;
import org.keycloak.userprofile.UserProfileContext;
import org.keycloak.userprofile.ValidationException;
import org.keycloak.testsuite.user.profile.config.UPAttribute;
import org.keycloak.testsuite.user.profile.config.UPAttributeRequirements;
import org.keycloak.testsuite.user.profile.config.UPAttributeValidation;
import org.keycloak.testsuite.user.profile.config.UPConfig;
import org.keycloak.util.JsonSerialization;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class UserProfileConfigTest extends AbstractUserProfileTest {

	@Override
	public void configureTestRealm(RealmRepresentation testRealm) {
		// no-op
	}

	@Test
	public void testInvalidConfigSetIntoComponent() {
		getTestingClient().server().run((RunOnServer) UserProfileConfigTest::testInvalidConfigSetIntoComponent);
	}

	private static void testInvalidConfigSetIntoComponent(KeycloakSession session) {
		configureSessionRealm(session);
		DynamicUserProfileProvider provider = getDynamicUserProfileProvider(session);
		ComponentModel component = provider.getComponentModel();

		assertNotNull(component);

		try {
			provider.setConfiguration("{\"validateConfigAttribute\": true}");
			fail("Should fail validation");
		} catch (ComponentValidationException ve) {
			// OK
		}

	}

	@Test
	public void testDefaultConfigForUpdateProfile() {
		getTestingClient().server().run((RunOnServer) UserProfileConfigTest::testDefaultConfigForUpdateProfile);
	}

	private static void testDefaultConfigForUpdateProfile(KeycloakSession session) throws IOException {
		configureSessionRealm(session);
		DynamicUserProfileProvider provider = getDynamicUserProfileProvider(session);
		ComponentModel component = provider.getComponentModel();

		assertNotNull(component);

		// failed required validations
		UserProfile profile = provider.create(UserProfileContext.UPDATE_PROFILE, Collections.emptyMap());

		try {
			profile.validate();
			fail("Should fail validation");
		} catch (ValidationException ve) {
			assertTrue(ve.isAttributeOnError(UserModel.USERNAME));
		}

		Map<String, Object> attributes = new HashMap<>();

		attributes.put(UserModel.FIRST_NAME, "");
		attributes.put(UserModel.LAST_NAME, "");
		attributes.put(UserModel.EMAIL, "");

		profile = provider.create(UserProfileContext.UPDATE_PROFILE, attributes);

		try {
			profile.validate();
			fail("Should fail validation");
		} catch (ValidationException ve) {
			assertTrue(ve.isAttributeOnError(UserModel.USERNAME));
			assertTrue(ve.isAttributeOnError(UserModel.FIRST_NAME));
			assertTrue(ve.isAttributeOnError(UserModel.LAST_NAME));
			assertTrue(ve.isAttributeOnError(UserModel.EMAIL));
		}

		UPConfig config = new UPConfig();
		UPAttribute attribute = new UPAttribute();

		attribute.setName(UserModel.USERNAME);

		Map<String, Object> validatorConfig = new HashMap<>();

		validatorConfig.put("min", 3);

		attribute.addValidation(new UPAttributeValidation("length", validatorConfig));

		config.addAttribute(attribute);

		provider.setConfiguration(JsonSerialization.writeValueAsString(config));

		attributes.put(UserModel.USERNAME, "us");

		profile = provider.create(UserProfileContext.UPDATE_PROFILE, attributes);

		try {
			profile.validate();
			fail("Should fail validation");
		} catch (ValidationException ve) {
			assertTrue(ve.isAttributeOnError(UserModel.USERNAME));
			assertTrue(ve.hasError("badLenghtUsernameMessage"));
		}
	}

	@Test
	public void testAdditionalValidationForUsername() {
		getTestingClient().server().run((RunOnServer) UserProfileConfigTest::testAdditionalValidationForUsername);
	}

	private static void testAdditionalValidationForUsername(KeycloakSession session) throws IOException {
		configureSessionRealm(session);
		DynamicUserProfileProvider provider = getDynamicUserProfileProvider(session);
		ComponentModel component = provider.getComponentModel();

		assertNotNull(component);

		UPConfig config = new UPConfig();
		UPAttribute attribute = new UPAttribute();

		attribute.setName(UserModel.USERNAME);

		Map<String, Object> validatorConfig = new HashMap<>();

		validatorConfig.put("min", 4);

		attribute.addValidation(new UPAttributeValidation("length", validatorConfig));

		config.addAttribute(attribute);

		provider.setConfiguration(JsonSerialization.writeValueAsString(config));

		Map<String, Object> attributes = new HashMap<>();

		attributes.put(UserModel.USERNAME, "us");

		UserProfile profile = provider.create(UserProfileContext.UPDATE_PROFILE, attributes);

		try {
			profile.validate();
			fail("Should fail validation");
		} catch (ValidationException ve) {
			assertTrue(ve.isAttributeOnError(UserModel.USERNAME));
			assertTrue(ve.hasError("badLenghtUsernameMessage"));
		}

		attributes.put(UserModel.USERNAME, "user");

		profile = provider.create(UserProfileContext.UPDATE_PROFILE, attributes);

		profile.validate();

		provider.setConfiguration(null);

		attributes.put(UserModel.USERNAME, "us");

		profile = provider.create(UserProfileContext.UPDATE_PROFILE, attributes);

		profile.validate();
	}

	@Test
	public void testCustomAttribute() {
		getTestingClient().server().run((RunOnServer) UserProfileConfigTest::testCustomAttribute);
	}

	private static void testCustomAttribute(KeycloakSession session) throws IOException {
		configureSessionRealm(session);
		DynamicUserProfileProvider provider = getDynamicUserProfileProvider(session);
		ComponentModel component = provider.getComponentModel();

		assertNotNull(component);

		UPConfig config = new UPConfig();
		UPAttribute attribute = new UPAttribute();

		attribute.setName("address");

		UPAttributeRequirements requirements = new UPAttributeRequirements();

		requirements.setAlways(true);

		attribute.setRequirements(requirements);

		config.addAttribute(attribute);

		provider.setConfiguration(JsonSerialization.writeValueAsString(config));

		Map<String, Object> attributes = new HashMap<>();

		attributes.put(UserModel.USERNAME, "user");

		UserProfile profile = provider.create(UserProfileContext.UPDATE_PROFILE, attributes);

		try {
			profile.validate();
			fail("Should fail validation");
		} catch (ValidationException ve) {
			assertTrue(ve.isAttributeOnError("address"));
		}
	}
}
