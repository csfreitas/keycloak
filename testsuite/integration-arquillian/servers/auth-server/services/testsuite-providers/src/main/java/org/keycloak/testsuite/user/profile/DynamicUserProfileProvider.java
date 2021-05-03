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

import static org.keycloak.common.util.ObjectUtil.isBlank;
import static org.keycloak.testsuite.user.profile.config.UPConfigParser.readConfig;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.jboss.logging.Logger;
import org.keycloak.component.AmphibianProviderFactory;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.validation.Validation;
import org.keycloak.userprofile.AttributeContext;
import org.keycloak.userprofile.AttributeMetadata;
import org.keycloak.userprofile.AttributeValidatorMetadata;
import org.keycloak.userprofile.UserProfileContext;
import org.keycloak.userprofile.UserProfileMetadata;
import org.keycloak.userprofile.UserProfileProvider;
import org.keycloak.testsuite.user.profile.config.UPAttribute;
import org.keycloak.testsuite.user.profile.config.UPAttributeRequirements;
import org.keycloak.testsuite.user.profile.config.UPAttributeValidation;
import org.keycloak.testsuite.user.profile.config.UPConfig;
import org.keycloak.testsuite.user.profile.config.UPConfigParser;
import org.keycloak.testsuite.user.profile.config.UPConfigUtils;
import org.keycloak.userprofile.legacy.AbstractUserProfileProvider;
import org.keycloak.userprofile.legacy.Validators;

import com.google.common.io.CharStreams;

/**
 * {@link UserProfileProvider} loading configuration from the changeable JSON
 * file stored in component config. Parsed configuration is cached.
 * 
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 * @author Vlastimil Elias <velias@redhat.com>
 */
public class DynamicUserProfileProvider extends AbstractUserProfileProvider<DynamicUserProfileProvider>
		implements AmphibianProviderFactory<DynamicUserProfileProvider> {

	private static final Logger LOG = Logger.getLogger(DynamicUserProfileProvider.class);

	public static final String ID = "dynamic-userprofile-provider";
	private static final String PARSED_CONFIG_COMPONENT_KEY = "kc.user.profile.metadata";

	public static final String UP_PIECE_COMPONENT_CONFIG_KEY_BASE = "config-piece-";
	public static final String UP_PIECES_COUNT_COMPONENT_CONFIG_KEY = "config-pieces-count";
	protected static final String SYSTEM_DEFAULT_CONFIG_RESOURCE = "/keycloak-default-user-profile.json";

	private String RAW_SYSTEM_DEFAULT_CONFIG;

	public DynamicUserProfileProvider() {
		// for reflection
	}

	public DynamicUserProfileProvider(KeycloakSession session,
			Map<UserProfileContext, UserProfileMetadata> metadataRegistry) {
		super(session, metadataRegistry);
	}

	@Override
	public String getId() {
		return ID;
	}

	@Override
	protected DynamicUserProfileProvider create(KeycloakSession session,
			Map<UserProfileContext, UserProfileMetadata> metadataRegistry) {
		return new DynamicUserProfileProvider(session, metadataRegistry);
	}

	@Override
	protected UserProfileMetadata configureUserProfile(UserProfileMetadata metadata) {
		LOG.debug("configureUserProfile(UserProfileMetadata metadata):" + metadata);
		return metadata;
	}

	@Override
	protected UserProfileMetadata configureUserProfile(UserProfileMetadata metadata, KeycloakSession session) {

		LOG.debugf("configureUserProfile(metadata, session): %s", metadata);

		ComponentModel model = getComponentModelOrCreate(session);
		Map<UserProfileContext, UserProfileMetadata> metadataMap = model.getNote(PARSED_CONFIG_COMPONENT_KEY);

		// not cached, create a note with cache
		if (metadataMap == null) {
			metadataMap = new HashMap<>();
			model.setNote(PARSED_CONFIG_COMPONENT_KEY, metadataMap);
		}

		return metadataMap.computeIfAbsent(metadata.getContext(),
				(context) -> decorateUserProfileForCache(metadata, model));
	}

	@Override
	public String getHelpText() {
		return null;
	}

	@Override
	public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel model)
			throws ComponentValidationException {

		LOG.debug("validateConfiguration() realm: " + realm + " model: " + model);

		UPConfig upc;
		String upConfigJson = getConfigJsonFromComponentModel(model);

		if (!isBlank(upConfigJson)) {
			try {
				upc = readConfig(new ByteArrayInputStream(upConfigJson.getBytes("UTF-8")));

				// validate new configuration
				List<String> errors = UPConfigParser.validateConfiguration(upc);
				if (!errors.isEmpty()) {
					throw new ComponentValidationException(
							"UserProfile configuration is invalid: " + errors.toString());
				}
			} catch (IOException e) {
				throw new ComponentValidationException(
						"UserProfile configuration is invalid due to JSON parsing error: " + e.getMessage(), e);
			}
		}

		// delete cache so new config is parsed and applied next time it is required
		// throught #configureUserProfile(metadata, session)
		if (model != null)
			model.setNote(PARSED_CONFIG_COMPONENT_KEY, new HashMap<>());
	}

	@Override
	public String getConfiguration() {
		String cfg = getConfigJsonFromComponentModel(getComponentModel());
		if (Validation.isBlank(cfg)) {
			return RAW_SYSTEM_DEFAULT_CONFIG;
		}

		return cfg;
	}

	@Override
	public void setConfiguration(String configuration) {
		ComponentModel component = getComponentModel();
		if (isBlank(configuration)) {
			removeConfigJsonFromComponentModel(component);
		} else {
			setConfigJsonIntoComponentModel(component, configuration);
		}
		session.getContext().getRealm().updateComponent(component);
	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {
		try (Reader reader = new InputStreamReader(
				getClass().getResourceAsStream(SYSTEM_DEFAULT_CONFIG_RESOURCE))) {
			RAW_SYSTEM_DEFAULT_CONFIG = CharStreams.toString(reader);
		} catch (IOException e) {
			throw new RuntimeException("System Default UserProfile config loading error: " + e.getMessage(), e);
		}
	}

	private String getConfigJsonFromComponentModel(ComponentModel model) {
		if (model == null)
			return null;

		int count = model.get(UP_PIECES_COUNT_COMPONENT_CONFIG_KEY, 0);
		if (count < 1) {
			return null;
		}

		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < count; i++) {
			String v = model.get(UP_PIECE_COMPONENT_CONFIG_KEY_BASE + i);
			if (v != null)
				sb.append(v);
		}

		return sb.toString();
	}

	protected void removeConfigJsonFromComponentModel(ComponentModel model) {
		if (model == null)
			return;

		int count = model.get(UP_PIECES_COUNT_COMPONENT_CONFIG_KEY, 0);
		if (count < 1) {
			return;
		}

		for (int i = 0; i < count; i++) {
			model.getConfig().remove(UP_PIECE_COMPONENT_CONFIG_KEY_BASE + i);
		}
		model.getConfig().remove(UP_PIECES_COUNT_COMPONENT_CONFIG_KEY);
	}

	private void setConfigJsonIntoComponentModel(ComponentModel model, String configuration) {
		// remove old breakup
		removeConfigJsonFromComponentModel(model);
		// store new parts
		List<String> parts = UPConfigUtils.breakString(configuration, 3800);
		model.getConfig().putSingle(UP_PIECES_COUNT_COMPONENT_CONFIG_KEY, "" + parts.size());
		int i = 0;
		for (String part : parts) {
			model.getConfig().putSingle(UP_PIECE_COMPONENT_CONFIG_KEY_BASE + (i++), part);
		}
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return Collections.emptyList();
	}

	public ComponentModel getComponentModel() {
		return getComponentModelOrCreate(session);
	}

	/**
	 * Decorate basic metadata provided from {@link AbstractUserProfileProvider}
	 * based on 'per realm' configuration. This method is called for each
	 * {@link UserProfileContext} in each realm, and metadata are cached then and
	 * this method is called again only if configuration changes.
	 * 
	 * @param metadata base to be decorated based on configuration loaded from
	 *                 component model
	 * @param model    component model to get "per realm" configuration from
	 * @return decorated metadata
	 */
	private UserProfileMetadata decorateUserProfileForCache(UserProfileMetadata metadata, ComponentModel model) {
		UserProfileContext context = metadata.getContext();
		UPConfig parsedConfig = getParsedConfig(model);

		if (parsedConfig == null) {
			return metadata;
		}

		LOG.debugf("decorateUserProfile parses config for context: %s", context.toString());

		// need to clone otherwise changes to profile config are going to be reflected
		// in the default config
		UserProfileMetadata decoratedMetadata = metadata.clone();

		for (UPAttribute attrConfig : parsedConfig.getAttributes()) {
			String attributeName = attrConfig.getName();

			List<AttributeValidatorMetadata> validators = new ArrayList<>();

			List<UPAttributeValidation> validationsConfig = attrConfig.getValidations();
			if (validationsConfig != null) {
				for (UPAttributeValidation vc : validationsConfig) {
					validators.add(createConfiguredValidator(attrConfig, vc));
				}
			}

			UPAttributeRequirements rc = attrConfig.getRequirements();
			Predicate<AttributeContext> required = AttributeMetadata.NEVER_SELECT;
			if (rc != null && !(UserModel.USERNAME.equals(attributeName) || UserModel.EMAIL.equals(attributeName))) {
				// do not take requirements from config for username and email as they are
				// driven by business logic from parent!

				if (rc.isAlways() || UPConfigUtils.isRoleForContext(context, rc.getRoles())) {
					validators.add(createRequiredValidator(attrConfig));
					required = AttributeMetadata.ALWAYS_SELECT;
				} else if (UPConfigUtils.canBeAuthFlowContext(context) && rc.getScopes() != null
						&& !rc.getScopes().isEmpty()) {
					// for contexts executed from auth flow and with configured scopes requirement
					// we have to create required validation with scopes based selector
					required = (c) -> attributePredicateAuthFlowRequestedScope(rc.getScopes(),session.getContext().getClient());
					validators.add(createRequiredValidator(attrConfig));
				}
			}

			if (UserModel.USERNAME.equals(attributeName) || UserModel.EMAIL.equals(attributeName)) {
				// add format validators for special attributes which may exist from parent
				if (!validators.isEmpty()) {
					List<AttributeMetadata> atts = decoratedMetadata.getAttribute(attributeName);
					if (atts.isEmpty()) {
						// attribute metadata doesn't exist so we have to add it. We keep it optional as Abstract base doesn't require it.
						decoratedMetadata.addAttribute(attributeName, validators, false, AttributeMetadata.NEVER_SELECT).addAnnotations(attrConfig.getAnnotations());
					} else {
						// only add configured validators and annotations if attribute metadata exist
						atts.stream().forEach(c -> {c.addValidator(validators);c.addAnnotations(attrConfig.getAnnotations());});
					}
				}
			} else {
				decoratedMetadata.addAttribute(attributeName, validators, false, required).addAnnotations(attrConfig.getAnnotations());
			}
		}

		return decoratedMetadata;

	}

	/**
	 * Get parsed config file configured in model. Default one used if not
	 * configured.
	 * 
	 * @param model to take config from
	 * @return parsed configuration
	 */
	protected UPConfig getParsedConfig(ComponentModel model) {
		String upConfigJson = getConfigJsonFromComponentModel(model);

		if (!isBlank(upConfigJson)) {
			try {
				return readConfig(new ByteArrayInputStream(upConfigJson.getBytes("UTF-8")));
			} catch (IOException e) {
				throw new RuntimeException("UserProfile config for realm " + session.getContext().getRealm().getName()
						+ " is invalid:" + e.getMessage(), e);
			}
		}

		return null;
	}

	/**
	 * Predicate to select attributes for Authentication flow cases where requested
	 * scopes (including configured Default client scopes) are compared to set of
	 * scopes from user profile configuration.
	 * <p>
	 * This patches problem with some auth flows (eg. register) where
	 * authSession.getClientScopes() doesn't work correctly!
	 * 
	 * @param scopesConfigured to match
	 * @param client           we compare scopes for (so default scopes are
	 *                         considered)
	 * @return true if at least one requested scope matches at least one configured
	 *         scope
	 */
	protected boolean attributePredicateAuthFlowRequestedScope(List<String> scopesConfigured, ClientModel client) {
		// never match out of auth flow
		if (session.getContext().getAuthenticationSession() == null) {
			return false;
		}

		return getAuthFlowRequestedScopeNames(client).stream().anyMatch(scopesConfigured::contains);
	}

	protected Set<String> getAuthFlowRequestedScopeNames(ClientModel client) {
		String requestedScopesString = session.getContext().getAuthenticationSession()
				.getClientNote(OIDCLoginProtocol.SCOPE_PARAM);
		return TokenManager.getRequestedClientScopes(requestedScopesString, client).map((csm) -> csm.getName())
				.collect(Collectors.toSet());
	}

	/**
	 * Get componenet to store our "per realm" configuration into.
	 * 
	 * @param session to be used, and take realm from
	 * @return componenet
	 */
	protected ComponentModel getComponentModelOrCreate(KeycloakSession session) {
		RealmModel realm = session.getContext().getRealm();
		ComponentModel model = realm.getComponentsStream(realm.getId(), UserProfileProvider.class.getName()).findAny()
				.orElseGet(() -> {
					ComponentModel configModel = new DynamicUserProfileModel();

					realm.addComponentModel(configModel);

					return configModel;
				});

		return model;
	}

	/**
	 * Create validator for 'required' validation.
	 * 
	 * @return validator
	 */
	protected AttributeValidatorMetadata createRequiredValidator(UPAttribute attrConfig) {
		String msg = "missing" + UPConfigUtils.capitalizeFirstLetter(attrConfig.getName()) + "Message";
		return Validators.create(msg, Validators.requiredByAttributeMetadata());
	}

	/**
	 * Create validator for validation configured in the user profile config.
	 * 
	 * @param attrConfig to create validator for
	 * @return validator
	 */
	protected AttributeValidatorMetadata createConfiguredValidator(UPAttribute attrConfig,
			UPAttributeValidation validationConfig) {
		// TODO UserProfile - integrate Validation SPI
		if ("length".equals(validationConfig.getValidator()))
			return Validators.create("badLenght"+ UPConfigUtils.capitalizeFirstLetter(attrConfig.getName()) +"Message",
					Validators.length(validationConfig.getConfig()));
		else if ("emailFormat".equals(validationConfig.getValidator()))
			return Validators.create("invalidEmailMessage", Validators.isEmailValid());
		else
			throw new RuntimeException("Unsupported UserProfile validator " + validationConfig.getValidator());
	}

}
