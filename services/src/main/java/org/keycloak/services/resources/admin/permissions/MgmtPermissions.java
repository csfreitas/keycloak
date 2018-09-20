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
package org.keycloak.services.resources.admin.permissions;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.AuthorizationProviderFactory;
import org.keycloak.authorization.common.DefaultEvaluationContext;
import org.keycloak.authorization.common.KeycloakIdentity;
import org.keycloak.authorization.common.UserModelIdentity;
import org.keycloak.authorization.identity.Identity;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.model.Scope;
import org.keycloak.authorization.permission.ResourcePermission;
import org.keycloak.authorization.policy.evaluation.DecisionPermissionCollector;
import org.keycloak.authorization.policy.evaluation.DefaultEvaluation;
import org.keycloak.authorization.policy.evaluation.EvaluationContext;
import org.keycloak.authorization.policy.evaluation.Result;
import org.keycloak.authorization.store.ResourceServerStore;
import org.keycloak.authorization.util.Permissions;
import org.keycloak.models.AdminRoles;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.representations.idm.authorization.Permission;
import org.keycloak.services.ForbiddenException;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.services.resources.admin.AdminAuth;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
class MgmtPermissions implements AdminPermissionEvaluator, AdminPermissionManagement, RealmsPermissionEvaluator {
    private static final Logger logger = Logger.getLogger(MgmtPermissions.class);

    protected RealmModel realm;
    protected KeycloakSession session;
    protected AuthorizationProvider authz;
    protected AdminAuth auth;
    protected Identity identity;
    protected UserModel admin;
    protected RealmModel adminsRealm;
    protected ResourceServer realmResourceServer;
    protected UserPermissions users;
    protected GroupPermissions groups;
    protected RealmPermissions realmPermissions;
    protected ClientPermissions clientPermissions;
    protected IdentityProviderPermissions idpPermissions;


    MgmtPermissions(KeycloakSession session, RealmModel realm) {
        this.session = session;
        this.realm = realm;
        KeycloakSessionFactory keycloakSessionFactory = session.getKeycloakSessionFactory();
        AuthorizationProviderFactory factory = (AuthorizationProviderFactory) keycloakSessionFactory.getProviderFactory(AuthorizationProvider.class);
        this.authz = factory.create(session, realm);
    }

    MgmtPermissions(KeycloakSession session, RealmModel realm, AdminAuth auth) {
        this(session, realm);
        this.auth = auth;
        this.admin = auth.getUser();
        this.adminsRealm = auth.getRealm();
        if (!auth.getRealm().equals(realm)
                && !auth.getRealm().equals(new RealmManager(session).getKeycloakAdminstrationRealm())) {
            throw new ForbiddenException();
        }
        initIdentity(session, auth);
    }
    MgmtPermissions(KeycloakSession session, AdminAuth auth) {
        this.session = session;
        this.auth = auth;
        this.admin = auth.getUser();
        this.adminsRealm = auth.getRealm();
        initIdentity(session, auth);
    }

    private void initIdentity(KeycloakSession session, AdminAuth auth) {
        if (auth.getToken().hasAudience(Constants.ADMIN_CLI_CLIENT_ID)
                || auth.getToken().hasAudience(Constants.ADMIN_CONSOLE_CLIENT_ID)) {
            this.identity = new UserModelIdentity(auth.getRealm(), auth.getUser());

        } else {
            this.identity = new KeycloakIdentity(auth.getToken(), session);
        }
    }

    MgmtPermissions(KeycloakSession session, RealmModel adminsRealm, UserModel admin) {
        this.session = session;
        this.admin = admin;
        this.adminsRealm = adminsRealm;
        this.identity = new UserModelIdentity(adminsRealm, admin);
    }

    MgmtPermissions(KeycloakSession session, RealmModel realm, RealmModel adminsRealm, UserModel admin) {
        this(session, realm);
        this.admin = admin;
        this.adminsRealm = adminsRealm;
        this.identity = new UserModelIdentity(realm, admin);
    }

    @Override
    public ClientModel getRealmManagementClient() {
        ClientModel client = null;
        if (realm.getName().equals(Config.getAdminRealm())) {
            client = realm.getClientByClientId(Config.getAdminRealm() + "-realm");
        } else {
            client = realm.getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID);

        }
        return client;
    }

    @Override
    public AuthorizationProvider authz() {
        return authz;
    }



    @Override
    public void requireAnyAdminRole() {
        if (!hasAnyAdminRole()) {
            throw new ForbiddenException();
        }
    }

    public boolean hasAnyAdminRole() {
        return hasOneAdminRole(AdminRoles.ALL_REALM_ROLES);
    }

    public boolean hasAnyAdminRole(RealmModel realm) {
        return hasOneAdminRole(realm, AdminRoles.ALL_REALM_ROLES);
    }

    public boolean hasOneAdminRole(String... adminRoles) {
        String clientId;
        RealmModel realm = this.realm;
        return hasOneAdminRole(realm, adminRoles);
    }

    public boolean hasOneAdminRole(RealmModel realm, String... adminRoles) {
        String clientId;
        RealmManager realmManager = new RealmManager(session);
        if (adminsRealm.equals(realmManager.getKeycloakAdminstrationRealm())) {
            clientId = realm.getMasterAdminClient().getClientId();
        } else if (adminsRealm.equals(realm)) {
            clientId = realm.getClientByClientId(realmManager.getRealmAdminClientId(realm)).getClientId();
        } else {
            return false;
        }
        for (String adminRole : adminRoles) {
            if (identity.hasClientRole(clientId, adminRole)) return true;
        }
        return false;
    }


    public boolean isAdminSameRealm() {
        return auth == null || realm.getId().equals(auth.getRealm().getId());
    }

    @Override
    public AdminAuth adminAuth() {
        return auth;
    }

    public Identity identity() {
        return identity;
    }

    public UserModel admin() {
        return admin;
    }

    public RealmModel adminsRealm() {
        return adminsRealm;
    }


    @Override
    public RolePermissions roles() {
        return new RolePermissions(session, realm, authz, this);
    }

    @Override
    public UserPermissions users() {
        if (users != null) return users;
        users = new UserPermissions(session, realm, authz, this);
        return users;
    }

    @Override
    public RealmPermissions realm() {
        if (realmPermissions != null) return realmPermissions;
        realmPermissions = new RealmPermissions(session, realm, authz, this);
        return realmPermissions;
    }

    @Override
    public ClientPermissions clients() {
        if (clientPermissions != null) return clientPermissions;
        clientPermissions = new ClientPermissions(session, realm, authz, this);
        return clientPermissions;
    }

    @Override
    public IdentityProviderPermissions idps() {
        if (idpPermissions != null) return idpPermissions;
        idpPermissions = new IdentityProviderPermissions(session, realm, authz, this);
        return idpPermissions;
    }

    @Override
    public GroupPermissions groups() {
        if (groups != null) return groups;
        groups = new GroupPermissions(session, realm, authz, this);
        return groups;
    }

    @Override
    public ResourceServer realmResourceServer() {
        if (realmResourceServer != null) return realmResourceServer;
        ClientModel client = getRealmManagementClient();
        if (client == null) return null;
        ResourceServerStore resourceServerStore = authz.getStoreFactory().getResourceServerStore();
        realmResourceServer = resourceServerStore.findById(client.getId());
        return realmResourceServer;

    }

    public ResourceServer initializeRealmResourceServer() {
        if (realmResourceServer != null) return realmResourceServer;
        ClientModel client = getRealmManagementClient();
        realmResourceServer = authz.getStoreFactory().getResourceServerStore().findById(client.getId());
        if (realmResourceServer == null) {
            realmResourceServer = authz.getStoreFactory().getResourceServerStore().create(client.getId());
        }
        return realmResourceServer;
    }

    protected Scope manageScope;
    protected Scope viewScope;

    public void initializeRealmDefaultScopes() {
        ResourceServer server = initializeRealmResourceServer();
        manageScope = initializeRealmScope(MgmtPermissions.MANAGE_SCOPE);
        viewScope = initializeRealmScope(MgmtPermissions.VIEW_SCOPE);
    }

    public Scope initializeRealmScope(String name) {
        ResourceServer server = initializeRealmResourceServer();
        Scope scope  = authz.getStoreFactory().getScopeStore().findByName(name, server.getId());
        if (scope == null) {
            scope = authz.getStoreFactory().getScopeStore().create(name, server);
        }
        return scope;
    }

    public Scope initializeScope(String name, ResourceServer server) {
        Scope scope  = authz.getStoreFactory().getScopeStore().findByName(name, server.getId());
        if (scope == null) {
            scope = authz.getStoreFactory().getScopeStore().create(name, server);
        }
        return scope;
    }



    public Scope realmManageScope() {
        if (manageScope != null) return manageScope;
        manageScope = realmScope(MgmtPermissions.MANAGE_SCOPE);
        return manageScope;
    }


    public Scope realmViewScope() {
        if (viewScope != null) return viewScope;
        viewScope = realmScope(MgmtPermissions.VIEW_SCOPE);
        return viewScope;
    }

    public Scope realmScope(String scope) {
        ResourceServer server = realmResourceServer();
        if (server == null) return null;
        return authz.getStoreFactory().getScopeStore().findByName(scope, server.getId());
    }

    public boolean evaluatePermission(Resource resource, Scope scope, ResourceServer resourceServer) {
        return evaluatePermission(new ArrayList<>(Arrays.asList(resource)), scope, resourceServer);
    }

    public boolean evaluatePermission(List<Resource> resources, Scope scope, ResourceServer resourceServer) {
        Identity identity = identity();
        if (identity == null) {
            throw new RuntimeException("Identity of admin is not set for permission query");
        }
        return evaluatePermission(resources, scope, resourceServer, identity, null);
    }

    public boolean evaluatePermission(List<Resource> resources, Scope scope, ResourceServer resourceServer, Consumer<ResourcePermission> consumer) {
        return evaluatePermission(resources, Arrays.asList(scope), resourceServer, consumer);
    }

    public boolean evaluatePermission(List<Resource> resources, List<Scope> scopes, ResourceServer resourceServer, Consumer<ResourcePermission> consumer) {
        Identity identity = identity();
        if (identity == null) {
            throw new RuntimeException("Identity of admin is not set for permission query");
        }
        return evaluatePermission(resources, scopes, resourceServer, identity, consumer);
    }

    public boolean evaluatePermission(Resource resource, Scope scope, ResourceServer resourceServer, Identity identity) {
        return evaluatePermission(new ArrayList<>(Arrays.asList(resource)), scope, resourceServer, identity, null);
    }

    public boolean evaluatePermission(List<Resource> resources, Scope scope, ResourceServer resourceServer, Identity identity, Consumer<ResourcePermission> consumer) {
        return evaluatePermission(resources, Arrays.asList(scope), resourceServer, identity, consumer);
    }

    public boolean evaluatePermission(List<Resource> resources, List<Scope> scopes, ResourceServer resourceServer, Identity identity, Consumer<ResourcePermission> consumer) {
        EvaluationContext context = new DefaultEvaluationContext(identity, session);
        return evaluatePermission(resources, scopes, resourceServer, context, consumer);
    }

    public boolean evaluatePermission(Resource resource, Scope scope, ResourceServer resourceServer, EvaluationContext context) {
        return evaluatePermission(new ArrayList<>(Arrays.asList(resource)), scope, resourceServer, context, null);
    }

    public boolean evaluatePermission(List<Resource> resources, Scope scope, ResourceServer resourceServer, EvaluationContext context, Consumer<ResourcePermission> consumer) {
        return evaluatePermission(resources, Arrays.asList(scope), resourceServer, context, consumer);
    }

    public boolean evaluatePermission(List<Resource> resources, List<Scope> scope, ResourceServer resourceServer, EvaluationContext context, Consumer<ResourcePermission> consumer) {
        RealmModel oldRealm = session.getContext().getRealm();
        try {
            session.getContext().setRealm(realm);
            List<ResourcePermission> permissions = resources.stream().map(resource1 -> new ResourcePermission(resource1, scope, resourceServer)).collect(Collectors.toList());

            authz.evaluators().from(permissions, context).evaluate(new DecisionPermissionCollector(authz, resourceServer, null) {
                @Override
                protected void onDeny(ResourcePermission permission) {
                    if (consumer != null) {
                        consumer.accept(permission);
                    }
                    resources.remove(permission.getResource());
                }
            });
        } finally {
            session.getContext().setRealm(oldRealm);
        }

        return !resources.isEmpty();
    }

    @Override
    public boolean canView(RealmModel realm) {
        return hasOneAdminRole(realm, AdminRoles.VIEW_REALM, AdminRoles.MANAGE_REALM);
    }

    @Override
    public boolean isAdmin(RealmModel realm) {
        return hasAnyAdminRole(realm);
    }

    @Override
    public boolean isAdmin() {
        RealmManager realmManager = new RealmManager(session);
        if (adminsRealm.equals(realmManager.getKeycloakAdminstrationRealm())) {
            if (identity.hasRealmRole(AdminRoles.ADMIN) || identity.hasRealmRole(AdminRoles.CREATE_REALM)) {
                return true;
            }
            for (RealmModel realm : session.realms().getRealms()) {
                if (isAdmin(realm)) return true;
            }
            return false;
        } else {
            return isAdmin(adminsRealm);
        }
    }

    @Override
    public boolean canCreateRealm() {
        RealmManager realmManager = new RealmManager(session);
        if (!auth.getRealm().equals(realmManager.getKeycloakAdminstrationRealm())) {
           return false;
        }
        return identity.hasRealmRole(AdminRoles.CREATE_REALM);
    }

    @Override
    public void requireCreateRealm() {
        if (!canCreateRealm()) {
            throw new ForbiddenException();
        }
    }




}
