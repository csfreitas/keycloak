/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.testsuite.user.profile.config;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.fasterxml.jackson.databind.JsonMappingException;
import org.junit.Assert;
import org.junit.Test;

/**
 * Unit test for {@link UPConfigParser} functionality
 * 
 * @author Vlastimil Elias <velias@redhat.com>
 *
 */
public class UPConfigParserTest {

    @Test
    public void attributeNameIsValid() {
        // few invalid cases
        Assert.assertFalse(UPConfigParser.attributeNameIsValid(""));
        Assert.assertFalse(UPConfigParser.attributeNameIsValid(" "));
        Assert.assertFalse(UPConfigParser.attributeNameIsValid("a b"));
        Assert.assertFalse(UPConfigParser.attributeNameIsValid("a*b"));
        Assert.assertFalse(UPConfigParser.attributeNameIsValid("a%b"));
        Assert.assertFalse(UPConfigParser.attributeNameIsValid("a$b"));

        // few valid cases
        Assert.assertTrue(UPConfigParser.attributeNameIsValid("a-b"));
        Assert.assertTrue(UPConfigParser.attributeNameIsValid("a.b"));
        Assert.assertTrue(UPConfigParser.attributeNameIsValid("a_b"));
        Assert.assertTrue(UPConfigParser.attributeNameIsValid("a3B"));
    }

    @Test
    public void loadConfigurationFromJsonFile() throws IOException {
        UPConfig config = UPConfigParser.readConfig(getValidConfigFileIS());

        // only basic assertion to check config is loaded, more detailed tests follow
        Assert.assertEquals(5, config.getAttributes().size());
    }

    @Test
    public void parseConfigurationFile_OK() throws IOException {
        UPConfig config = loadValidConfig();

        Assert.assertNotNull(config);

        // assert *** attributes ***
        Assert.assertEquals(5, config.getAttributes().size());
        UPAttribute attEmail = config.getAttributes().get(1);
        Assert.assertNotNull(attEmail);
        Assert.assertEquals("email", attEmail.getName());
        // validation
        Assert.assertEquals(3, attEmail.getValidations().size());
        Assert.assertEquals("length", attEmail.getValidations().get(0).getValidator());
        Assert.assertEquals(1, attEmail.getValidations().get(0).getConfig().size());
        Assert.assertEquals(255, attEmail.getValidations().get(0).getConfig().get("max"));
        // annotations
        Assert.assertEquals("userEmailFormFieldHint", attEmail.getAnnotations().get("formHintKey"));
        // permissions
        Assert.assertNotNull(attEmail.getPermissions());
        Assert.assertNotNull(attEmail.getPermissions().getEdit());
        Assert.assertEquals(1, attEmail.getPermissions().getEdit().size());
        Assert.assertTrue(attEmail.getPermissions().getEdit().contains("admin"));
        Assert.assertNotNull(attEmail.getPermissions().getView());
        Assert.assertEquals(2, attEmail.getPermissions().getView().size());
        Assert.assertTrue(attEmail.getPermissions().getView().contains("admin"));
        Assert.assertTrue(attEmail.getPermissions().getView().contains("user"));
        // requirements
        Assert.assertNotNull(attEmail.getRequirements());
        Assert.assertFalse(attEmail.getRequirements().isAlways());
        Assert.assertNull(attEmail.getRequirements().getScopes());
        Assert.assertNotNull(attEmail.getRequirements().getRoles());
        Assert.assertEquals(2, attEmail.getRequirements().getRoles().size());
    }

    /**
     * Parse valid JSON config from the test file for tests.
     * 
     * @return valid config
     * @throws IOException
     */
    private UPConfig loadValidConfig() throws IOException {
        return UPConfigParser.readConfig(getValidConfigFileIS());
    }

    private InputStream getValidConfigFileIS() {
        return getClass().getResourceAsStream("test-OK.json");
    }

    @Test(expected = JsonMappingException.class)
    public void parseConfigurationFile_invalidJsonFormat() throws IOException {
        UPConfigParser.readConfig(getClass().getResourceAsStream("test-invalidJsonFormat.json"));
    }

    @Test(expected = IOException.class)
    public void parseConfigurationFile_invalidType() throws IOException {
        UPConfigParser.readConfig(getClass().getResourceAsStream("test-invalidType.json"));
    }

    @Test(expected = IOException.class)
    public void parseConfigurationFile_unknownField() throws IOException {
        UPConfigParser.readConfig(getClass().getResourceAsStream("test-unknownField.json"));
    }

    @Test
    public void validateConfiguration_OK() throws IOException {
        List<String> errors = UPConfigParser.validateConfiguration(loadValidConfig());
        Assert.assertTrue(errors.isEmpty());
    }

    @Test
    public void validateConfiguration_attributeNameErrors() throws IOException {
        UPConfig config = loadValidConfig();

        UPAttribute attConfig = config.getAttributes().get(1);

        attConfig.setName(null);
        List<String> errors = UPConfigParser.validateConfiguration(config);
        Assert.assertEquals(1, errors.size());

        attConfig.setName(" ");
        errors = UPConfigParser.validateConfiguration(config);
        Assert.assertEquals(1, errors.size());

        // duplicate attribute name
        attConfig.setName("firstName");
        errors = UPConfigParser.validateConfiguration(config);
        Assert.assertEquals(1, errors.size());

        // attribute name format error - unallowed character
        attConfig.setName("ema il");
        errors = UPConfigParser.validateConfiguration(config);
        Assert.assertEquals(1, errors.size());
    }

    @Test
    public void validateConfiguration_attributePermissionsErrors() throws IOException {
        UPConfig config = loadValidConfig();

        UPAttribute attConfig = config.getAttributes().get(1);

        // no permissions configures at all
        attConfig.setPermissions(null);
        List<String> errors = UPConfigParser.validateConfiguration(config);
        Assert.assertEquals(0, errors.size());

        // no permissions structure fields configured
        UPAttributePermissions permsConfig = new UPAttributePermissions();
        attConfig.setPermissions(permsConfig);
        errors = UPConfigParser.validateConfiguration(config);
        Assert.assertEquals(2, errors.size());

        // valid if both are present, even empty
        permsConfig.setEdit(Collections.emptyList());
        permsConfig.setView(Collections.emptyList());
        attConfig.setPermissions(permsConfig);
        errors = UPConfigParser.validateConfiguration(config);
        Assert.assertEquals(0, errors.size());

        List<String> withInvRole = new ArrayList<>();
        withInvRole.add("invalid");

        // invalid role used for view
        permsConfig.setView(withInvRole);
        errors = UPConfigParser.validateConfiguration(config);
        Assert.assertEquals(1, errors.size());

        // invalid role used for edit also
        permsConfig.setEdit(withInvRole);
        errors = UPConfigParser.validateConfiguration(config);
        Assert.assertEquals(2, errors.size());
    }

    @Test
    public void validateConfiguration_attributeRequirementsErrors() throws IOException {
        UPConfig config = loadValidConfig();

        UPAttribute attConfig = config.getAttributes().get(1);

        // it is OK without requirements configures at all
        attConfig.setRequirements(null);
        List<String> errors = UPConfigParser.validateConfiguration(config);
        Assert.assertEquals(0, errors.size());

        // it is OK with empty config
        UPAttributeRequirements reqConfig = new UPAttributeRequirements();
        attConfig.setRequirements(reqConfig);
        errors = UPConfigParser.validateConfiguration(config);
        Assert.assertEquals(0, errors.size());
        //utility method test
        Assert.assertTrue(reqConfig.isNeverRequired());

        List<String> withInvRole = new ArrayList<>();
        withInvRole.add("invalid");

        // invalid role used
        reqConfig.setRoles(withInvRole);;
        errors = UPConfigParser.validateConfiguration(config);
        Assert.assertEquals(1, errors.size());
        Assert.assertFalse(reqConfig.isNeverRequired());

    }

    @Test
    public void validateConfiguration_attributeValidationsErrors() throws IOException {
        UPConfig config = loadValidConfig();

        UPAttributeValidation validationConfig = config.getAttributes().get(1).getValidations().get(0);

        validationConfig.setValidator(null);
        List<String> errors = UPConfigParser.validateConfiguration(config);
        Assert.assertEquals(1, errors.size());

        validationConfig.setValidator(" ");
        errors = UPConfigParser.validateConfiguration(config);
        Assert.assertEquals(1, errors.size());

        // TODO Validation SPI integration - test validation of the validator existence and validator config
        // validationConfig.setValidator("unknownValidator");
        // errors = UPConfigParser.validateConfiguration(config);
        // Assert.assertEquals(1, errors.size());
    }
}
