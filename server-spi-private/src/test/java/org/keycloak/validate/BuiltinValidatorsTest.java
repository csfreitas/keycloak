package org.keycloak.validate;

import static org.keycloak.validate.ValidatorConfig.configFromMap;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import org.junit.Assert;
import org.junit.Test;
import org.keycloak.validate.validators.IntegerNumberValidator;
import org.keycloak.validate.validators.LengthValidator;
import org.keycloak.validate.validators.PatternValidator;
import org.keycloak.validate.validators.UriValidator;

import com.google.common.collect.ImmutableMap;

public class BuiltinValidatorsTest {

	@Test
	public void validateLength() {

		Validator validator = Validators.lengthValidator();

		//null and empty values handling
		Assert.assertTrue(validator.validate(null, "name", configFromMap(ImmutableMap.of(LengthValidator.KEY_MIN, 1))).isValid());
		Assert.assertTrue(validator.validate("", "name", configFromMap(ImmutableMap.of(LengthValidator.KEY_MIN, 1))).isValid());
		Assert.assertFalse(validator.validate(" ", "name", configFromMap(ImmutableMap.of(LengthValidator.KEY_MIN, 1))).isValid());
		Assert.assertTrue(validator.validate(" ", "name", configFromMap(ImmutableMap.of(LengthValidator.KEY_MAX, 10))).isValid());
		
		// min validation only
		Assert.assertTrue(validator.validate("tester", "name", configFromMap(ImmutableMap.of(LengthValidator.KEY_MIN, 1))).isValid());
		Assert.assertFalse(validator.validate("tester", "name", configFromMap(ImmutableMap.of(LengthValidator.KEY_MIN, 7))).isValid());

		// max validation only
		Assert.assertTrue(validator.validate("tester", "name", configFromMap(ImmutableMap.of(LengthValidator.KEY_MAX, 8))).isValid());
		Assert.assertFalse(validator.validate("tester", "name", configFromMap(ImmutableMap.of(LengthValidator.KEY_MAX, 4))).isValid());

		// both validations together
		ValidatorConfig config1 = configFromMap(ImmutableMap.of(LengthValidator.KEY_MIN, 3, LengthValidator.KEY_MAX, 4));
		Assert.assertFalse(validator.validate("te", "name", config1).isValid());
		Assert.assertTrue(validator.validate("tes", "name", config1).isValid());
		Assert.assertTrue(validator.validate("test", "name", config1).isValid());
		Assert.assertFalse(validator.validate("testr", "name", config1).isValid());

		// test value trimming performed by default
		Assert.assertFalse("trim not performed", validator.validate("t ", "name", configFromMap(ImmutableMap.of(LengthValidator.KEY_MIN, 2))).isValid());
		Assert.assertFalse("trim not performed", validator.validate(" t", "name", configFromMap(ImmutableMap.of(LengthValidator.KEY_MIN, 2))).isValid());

		// test value trimming disabled in config
		Assert.assertTrue("trim disabled but performed", validator.validate("t ", "name", configFromMap(ImmutableMap.of(LengthValidator.KEY_MIN, 2, LengthValidator.KEY_TRIM_DISABLED, true))).isValid());
	}
	
	@Test
	public void validateLength_ConfigValidation() {

		//invalid min and max config values
		ValidatorConfig config = new ValidatorConfig(ImmutableMap.of(LengthValidator.KEY_MIN, new Object(), LengthValidator.KEY_MAX, "invalid"));

		ValidationResult result = Validators.validatorConfigValidator().validate(config, LengthValidator.ID).toResult();

		Assert.assertFalse(result.isValid());
		ValidationError[] errors = result.getErrors().toArray(new ValidationError[0]);

		ValidationError error0 = errors[0];
		Assert.assertNotNull(error0);
		Assert.assertEquals(LengthValidator.ID, error0.getValidatorId());
		Assert.assertEquals(LengthValidator.KEY_MIN, error0.getInputHint());

		ValidationError error1 = errors[1];
		Assert.assertNotNull(error1);
		Assert.assertEquals(LengthValidator.ID, error1.getValidatorId());
		Assert.assertEquals(LengthValidator.KEY_MAX, error1.getInputHint());
		

		//empty config
		result = Validators.validatorConfigValidator().validate(null, LengthValidator.ID).toResult();
		Assert.assertEquals(2,result.getErrors().size());
		result = Validators.validatorConfigValidator().validate(ValidatorConfig.EMPTY, LengthValidator.ID).toResult();
		Assert.assertEquals(2,result.getErrors().size());
		
		//correct config
		Assert.assertTrue(Validators.validatorConfigValidator().validate(new ValidatorConfig(ImmutableMap.of(LengthValidator.KEY_MIN, "10")), LengthValidator.ID).toResult().isValid());
		Assert.assertTrue(Validators.validatorConfigValidator().validate(new ValidatorConfig(ImmutableMap.of(LengthValidator.KEY_MAX, "10")), LengthValidator.ID).toResult().isValid());
		Assert.assertTrue(Validators.validatorConfigValidator().validate(new ValidatorConfig(ImmutableMap.of(LengthValidator.KEY_MIN, "10",LengthValidator.KEY_MAX, "10")), LengthValidator.ID).toResult().isValid());
		
		//max is smaller than min
		Assert.assertFalse(Validators.validatorConfigValidator().validate(new ValidatorConfig(ImmutableMap.of(LengthValidator.KEY_MIN, "10",LengthValidator.KEY_MAX, "9")), LengthValidator.ID).toResult().isValid());
	}


	@Test
	public void validateEmail() {
		// this also validates StringFormatValidatorBase for simple values

		Validator validator = Validators.emailValidator();

		Assert.assertTrue(validator.validate(null, "email").isValid());
		Assert.assertTrue(validator.validate("", "email").isValid());
		Assert.assertTrue(validator.validate("admin@example.org", "email").isValid());
		Assert.assertTrue(validator.validate("admin+sds@example.org", "email").isValid());

		Assert.assertFalse(validator.validate(" ", "email").isValid());
		Assert.assertFalse(validator.validate("adminATexample.org", "email").isValid());
	}

	@Test
	public void validateStringFormatValidatorBaseForCollections() {

		Validator validator = Validators.emailValidator();

		List<String> valuesCollection = new ArrayList<>();

		Assert.assertTrue(validator.validate(valuesCollection, "email").isValid());

		valuesCollection.add("");
		Assert.assertTrue(validator.validate(valuesCollection, "email").isValid());
		valuesCollection.add("admin@example.org");
		Assert.assertTrue(validator.validate("admin@example.org", "email").isValid());

		// wrong value fails validation even it is not at first position
		valuesCollection.add(" ");
		Assert.assertFalse(validator.validate(valuesCollection, "email").isValid());

		valuesCollection.remove(valuesCollection.size() - 1);
		valuesCollection.add("adminATexample.org");
		Assert.assertFalse(validator.validate(valuesCollection, "email").isValid());

	}

	@Test
	public void validateNotBlank() {

		Validator validator = Validators.notBlankValidator();

		//simple String value
		Assert.assertTrue(validator.validate("tester", "username").isValid());
		Assert.assertFalse(validator.validate("", "username").isValid());
		Assert.assertFalse(validator.validate("   ", "username").isValid());
		Assert.assertFalse(validator.validate(null, "username").isValid());
		
		//collection as input
		Assert.assertTrue(validator.validate(Arrays.asList("a","b"), "username").isValid());
		Assert.assertFalse(validator.validate(new ArrayList<>(), "username").isValid());
		Assert.assertFalse(validator.validate(Arrays.asList(""), "username").isValid());
		Assert.assertFalse(validator.validate(Arrays.asList(" "), "username").isValid());
		Assert.assertFalse(validator.validate(Arrays.asList("a"," "), "username").isValid());
		Assert.assertFalse(validator.validate(Arrays.asList("a",new Object()), "username").isValid());
		
		//unsupported input type
		Assert.assertFalse(validator.validate(new Object(), "username").isValid());
	}

	@Test
	public void validateNotEmpty() {

		Validator validator = Validators.notEmptyValidator();

		Assert.assertTrue(validator.validate("tester", "username").isValid());
		Assert.assertTrue(validator.validate(" ", "username").isValid());
		Assert.assertTrue(validator.validate(Arrays.asList(1, 2, 3), "numberList").isValid());
		Assert.assertTrue(validator.validate(Collections.singleton("key"), "stringSet").isValid());
		Assert.assertTrue(validator.validate(Collections.singletonMap("key", "value"), "stringMap").isValid());
		
		Assert.assertFalse(validator.validate(null, "username").isValid());
		Assert.assertFalse(validator.validate("", "username").isValid());
		Assert.assertFalse(validator.validate(Collections.emptyList(), "emptyList").isValid());
		Assert.assertFalse(validator.validate(Collections.emptySet(), "emptySet").isValid());
		Assert.assertFalse(validator.validate(Collections.emptyMap(), "emptyMap").isValid());
	}

	@Test
	public void validateNumber() {

		Validator validator = Validators.numberValidator();

		//null value and empty String
		Assert.assertTrue(validator.validate(null, "null").isValid());
		Assert.assertTrue(validator.validate("", "emptyString").isValid());
	
		//simple values
		Assert.assertTrue(validator.validate(10, "age").isValid());
		Assert.assertTrue(validator.validate("10", "age").isValid());
		Assert.assertTrue(validator.validate("3.14", "pi").isValid());
		Assert.assertTrue(validator.validate("   3.14   ", "piWithBlank").isValid());

		Assert.assertFalse(validator.validate("a", "notAnumber").isValid());
		Assert.assertFalse(validator.validate(true, "true").isValid());
		
		//collections
		Assert.assertTrue(validator.validate(new ArrayList<>(), "age").isValid());
		Assert.assertTrue(validator.validate(Arrays.asList(""), "age").isValid());
		Assert.assertTrue(validator.validate(Arrays.asList(10), "age").isValid());
		Assert.assertTrue(validator.validate(Arrays.asList(" 10 "), "age").isValid());
		Assert.assertTrue(validator.validate(Arrays.asList("3.14"), "pi").isValid());
		Assert.assertTrue(validator.validate(Arrays.asList("3.14",10), "pi").isValid());
		
		Assert.assertFalse(validator.validate(Arrays.asList("a"), "notAnumber").isValid());
		Assert.assertFalse(validator.validate(Arrays.asList("3.14", "a"), "notANumberPresent").isValid());
		Assert.assertFalse(validator.validate(Arrays.asList("3.14", new Object()), "notANumberPresent").isValid());
		
	}
	
	@Test
	public void validateIntegerNumber() {

		Validator validator = Validators.integerNumberValidator();

		//null value and empty String
		Assert.assertTrue(validator.validate(null, "null").isValid());
		Assert.assertTrue(validator.validate("", "emptyString").isValid());
	
		//simple values
		Assert.assertTrue(validator.validate(10, "age").isValid());
		Assert.assertTrue(validator.validate("10", "age").isValid());

		Assert.assertFalse(validator.validate("3.14", "pi").isValid());
		Assert.assertFalse(validator.validate("   3.14   ", "piWithBlank").isValid());
		Assert.assertFalse(validator.validate("a", "notAnumber").isValid());
		Assert.assertFalse(validator.validate(true, "true").isValid());
		
		//collections
		Assert.assertTrue(validator.validate(new ArrayList<>(), "age").isValid());
		Assert.assertTrue(validator.validate(Arrays.asList(""), "age").isValid());
		Assert.assertTrue(validator.validate(Arrays.asList(10), "age").isValid());
		Assert.assertTrue(validator.validate(Arrays.asList(" 10 "), "age").isValid());
		
		Assert.assertFalse(validator.validate(Arrays.asList("3.14"), "pi").isValid());
		Assert.assertFalse(validator.validate(Arrays.asList("3.14",10), "pi").isValid());
		Assert.assertFalse(validator.validate(Arrays.asList("a"), "notAnumber").isValid());
		Assert.assertFalse(validator.validate(Arrays.asList("10", "a"), "notANumberPresent").isValid());
		Assert.assertFalse(validator.validate(Arrays.asList("10", new Object()), "notANumberPresent").isValid());
		
		//min only
		Assert.assertTrue(validator.validate("10", "name", configFromMap(ImmutableMap.of(IntegerNumberValidator.KEY_MIN, 1))).isValid());
		Assert.assertFalse(validator.validate("10", "name", configFromMap(ImmutableMap.of(IntegerNumberValidator.KEY_MIN, 100))).isValid());
		
		//max only
		Assert.assertFalse(validator.validate("10", "name", configFromMap(ImmutableMap.of(IntegerNumberValidator.KEY_MAX, 1))).isValid());
		Assert.assertTrue(validator.validate("10", "name", configFromMap(ImmutableMap.of(IntegerNumberValidator.KEY_MAX, 100))).isValid());
		
		//min and max
		Assert.assertFalse(validator.validate("9", "name", configFromMap(ImmutableMap.of(IntegerNumberValidator.KEY_MIN, 10, IntegerNumberValidator.KEY_MAX, 100))).isValid());
		Assert.assertTrue(validator.validate("10", "name", configFromMap(ImmutableMap.of(IntegerNumberValidator.KEY_MIN, 10, IntegerNumberValidator.KEY_MAX, 100))).isValid());
		Assert.assertTrue(validator.validate("100", "name", configFromMap(ImmutableMap.of(IntegerNumberValidator.KEY_MIN, 10, IntegerNumberValidator.KEY_MAX, 100))).isValid());
		Assert.assertFalse(validator.validate("101", "name", configFromMap(ImmutableMap.of(IntegerNumberValidator.KEY_MIN, 10, IntegerNumberValidator.KEY_MAX, 100))).isValid());
	}
	
	@Test
	public void validateIntegerNumber_ConfigValidation() {

		//invalid min and max config values
		ValidatorConfig config = new ValidatorConfig(ImmutableMap.of(IntegerNumberValidator.KEY_MIN, new Object(), IntegerNumberValidator.KEY_MAX, "invalid"));

		ValidationResult result = Validators.validatorConfigValidator().validate(config, IntegerNumberValidator.ID).toResult();

		Assert.assertFalse(result.isValid());
		ValidationError[] errors = result.getErrors().toArray(new ValidationError[0]);

		ValidationError error0 = errors[0];
		Assert.assertNotNull(error0);
		Assert.assertEquals(IntegerNumberValidator.ID, error0.getValidatorId());
		Assert.assertEquals(IntegerNumberValidator.KEY_MIN, error0.getInputHint());

		ValidationError error1 = errors[1];
		Assert.assertNotNull(error1);
		Assert.assertEquals(IntegerNumberValidator.ID, error1.getValidatorId());
		Assert.assertEquals(IntegerNumberValidator.KEY_MAX, error1.getInputHint());
		

		//empty config
		result = Validators.validatorConfigValidator().validate(null, IntegerNumberValidator.ID).toResult();
		Assert.assertEquals(0,result.getErrors().size());
		result = Validators.validatorConfigValidator().validate(ValidatorConfig.EMPTY, IntegerNumberValidator.ID).toResult();
		Assert.assertEquals(0,result.getErrors().size());
		
		//correct config
		Assert.assertTrue(Validators.validatorConfigValidator().validate(new ValidatorConfig(ImmutableMap.of(IntegerNumberValidator.KEY_MIN, "10")), IntegerNumberValidator.ID).toResult().isValid());
		Assert.assertTrue(Validators.validatorConfigValidator().validate(new ValidatorConfig(ImmutableMap.of(IntegerNumberValidator.KEY_MAX, "10")), IntegerNumberValidator.ID).toResult().isValid());
		Assert.assertTrue(Validators.validatorConfigValidator().validate(new ValidatorConfig(ImmutableMap.of(IntegerNumberValidator.KEY_MIN, "10",IntegerNumberValidator.KEY_MAX, "11")), IntegerNumberValidator.ID).toResult().isValid());
		
		//max is smaller than min
		Assert.assertFalse(Validators.validatorConfigValidator().validate(new ValidatorConfig(ImmutableMap.of(IntegerNumberValidator.KEY_MIN, "10",IntegerNumberValidator.KEY_MAX, "10")), IntegerNumberValidator.ID).toResult().isValid());
	}

	@Test
	public void validatePattern() {

		Validator validator = Validators.patternValidator();

		// Pattern object in the configuration
		ValidatorConfig config = configFromMap(Collections.singletonMap(PatternValidator.KEY_PATTERN, Pattern.compile("^start-.*-end$")));
		Assert.assertTrue(validator.validate("start-1234-end", "value", config).isValid());
		Assert.assertFalse(validator.validate("start___end", "value", config).isValid());

		// String in the configuration
		config = configFromMap(Collections.singletonMap(PatternValidator.KEY_PATTERN, "^start-.*-end$"));
		Assert.assertTrue(validator.validate("start-1234-end", "value", config).isValid());
		Assert.assertFalse(validator.validate("start___end", "value", config).isValid());
		
		//null and empty values handling
		//pattern not applied to null or empty string
		Assert.assertTrue(validator.validate(null, "value", config).isValid());
		Assert.assertTrue(validator.validate("", "value", config).isValid());
		//pattern is applied to blank string
		Assert.assertFalse(validator.validate(" ", "value", config).isValid());
	}

	@Test
	public void validateUri() throws Exception {

		Validator validator = Validators.uriValidator();

		Assert.assertTrue(validator.validate(null, "baseUrl").isValid());
		Assert.assertTrue(validator.validate("", "baseUrl").isValid());
		Assert.assertTrue(validator.validate("http://localhost:3000/", "baseUrl").isValid());
		Assert.assertTrue(validator.validate("https://localhost:3000/", "baseUrl").isValid());
		Assert.assertTrue(validator.validate("https://localhost:3000/#someFragment", "baseUrl").isValid());

		Assert.assertFalse(validator.validate(" ", "baseUrl").isValid());
		Assert.assertFalse(validator.validate("file:///somefile.txt", "baseUrl").isValid());
		Assert.assertFalse(validator.validate("invalidUrl++@23", "invalidUri").isValid());

		ValidatorConfig config = configFromMap(ImmutableMap.of(UriValidator.KEY_ALLOW_FRAGMENT, false));
		Assert.assertFalse(validator.validate("https://localhost:3000/#someFragment", "baseUrl", config).isValid());

		// it is also possible to call dedicated validation methods on a built-in validator
		Assert.assertTrue(Validators.uriValidator().validateUri(new URI("https://customurl"), Collections.singleton("https"), true, true));

		Assert.assertFalse(Validators.uriValidator().validateUri(new URI("http://customurl"), Collections.singleton("https"), true, true));
	}

}
