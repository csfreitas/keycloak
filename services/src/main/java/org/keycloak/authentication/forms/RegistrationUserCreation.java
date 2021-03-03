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

package org.keycloak.authentication.forms;

import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.userprofile.UserProfile;
import org.keycloak.userprofile.UserProfileProvider;

import javax.ws.rs.core.MultivaluedMap;
import java.util.List;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class RegistrationUserCreation implements FormAction, FormActionFactory {

    public static final String PROVIDER_ID = "registration-user-creation";

    @Override
    public String getHelpText() {
        return "This action must always be first! Validates the username of the user in validation phase.  In success phase, this will create the user in the database.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    @Override
    public void validate(ValidationContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        context.getEvent().detail(Details.REGISTER_METHOD, "form");

        KeycloakSession session = context.getSession();
        UserProfile profile = session.getProvider(UserProfileProvider.class).create(UserProfile.UserUpdateEvent.RegistrationUserCreation.name());

        try {
            profile.validate(formData);
        } catch (UserProfile.ProfileValidationException pve) {
            List<FormMessage> errors = Validation.getFormErrorsFromValidation(pve.getErrors());

            if (pve.hasError(Messages.EMAIL_EXISTS)) {
                context.error(Errors.EMAIL_IN_USE);
                formData.remove(RegistrationPage.FIELD_EMAIL);
            } else if (pve.hasError(Messages.MISSING_EMAIL, Messages.MISSING_USERNAME, Messages.INVALID_EMAIL)) {
                if (pve.hasError(Messages.INVALID_EMAIL))
                    formData.remove(Validation.FIELD_EMAIL);
                context.error(Errors.INVALID_REGISTRATION);
            } else if (pve.hasError(Messages.USERNAME_EXISTS)) {
                context.error(Errors.USERNAME_IN_USE);
                formData.remove(Validation.FIELD_USERNAME);
            }

            context.validationError(formData, errors);

            return;
        }

        String email = profile.getAttributes().getFirstValue(UserModel.EMAIL);

        context.getEvent().detail(Details.EMAIL, email);

        String username = profile.getAttributes().getFirstValue(UserModel.USERNAME);

        context.getEvent().detail(Details.USERNAME, username);

        if (context.getRealm().isRegistrationEmailAsUsername()) {
            context.getEvent().detail(Details.USERNAME, email);
        }

        context.success();
    }

    @Override
    public void buildPage(FormContext context, LoginFormsProvider form) {

    }

    @Override
    public void success(FormContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        String email = formData.getFirst(UserModel.EMAIL);
        String username = formData.getFirst(UserModel.USERNAME);

        if (context.getRealm().isRegistrationEmailAsUsername()) {
            username = email;
        }

        context.getEvent().detail(Details.USERNAME, username)
                .detail(Details.REGISTER_METHOD, "form")
                .detail(Details.EMAIL, email);

        KeycloakSession session = context.getSession();
        UserModel user = session.users().addUser(context.getRealm(), username);

        user.setEnabled(true);

        session.getProvider(UserProfileProvider.class).create(UserProfile.UserUpdateEvent.RegistrationUserCreation.name(), user).update(formData);

        context.getAuthenticationSession().setClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM, username);

        context.setUser(user);
        context.getEvent().user(user);
        context.getEvent().success();
        context.newEvent().event(EventType.LOGIN);
        context.getEvent().client(context.getAuthenticationSession().getClient().getClientId())
                .detail(Details.REDIRECT_URI, context.getAuthenticationSession().getRedirectUri())
                .detail(Details.AUTH_METHOD, context.getAuthenticationSession().getProtocol());
        String authType = context.getAuthenticationSession().getAuthNote(Details.AUTH_TYPE);
        if (authType != null) {
            context.getEvent().detail(Details.AUTH_TYPE, authType);
        }
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }


    @Override
    public void close() {

    }

    @Override
    public String getDisplayType() {
        return "Registration User Creation";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };
    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }
    @Override
    public FormAction create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
