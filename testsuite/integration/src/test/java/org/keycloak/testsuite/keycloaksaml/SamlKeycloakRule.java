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

package org.keycloak.testsuite.keycloaksaml;

import io.undertow.security.idm.Account;
import io.undertow.security.idm.Credential;
import io.undertow.security.idm.IdentityManager;
import io.undertow.server.HandlerWrapper;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.resource.Resource;
import io.undertow.server.handlers.resource.ResourceChangeListener;
import io.undertow.server.handlers.resource.ResourceManager;
import io.undertow.server.handlers.resource.URLResource;
import io.undertow.server.session.Session;
import io.undertow.server.session.SessionConfig;
import io.undertow.server.session.SessionManager;
import io.undertow.servlet.api.AuthMethodConfig;
import io.undertow.servlet.api.Deployment;
import io.undertow.servlet.api.DeploymentInfo;
import io.undertow.servlet.api.ListenerInfo;
import io.undertow.servlet.api.LoginConfig;
import io.undertow.servlet.api.SecurityConstraint;
import io.undertow.servlet.api.ServletInfo;
import io.undertow.servlet.api.WebResourceCollection;
import io.undertow.servlet.handlers.ServletRequestContext;
import io.undertow.servlet.util.SavedRequest;
import org.keycloak.adapters.elytron.KeycloakRoleDecoder;
import org.keycloak.adapters.saml.SamlAuthenticationError;
import org.keycloak.adapters.saml.elytron.KeycloakConfigurationServletListener;
import org.keycloak.adapters.spi.AuthChallenge;
import org.keycloak.adapters.spi.AuthOutcome;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.assertion.StatementAbstractType;
import org.keycloak.dom.saml.v2.assertion.SubjectType;
import org.keycloak.saml.common.constants.GeneralConstants;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.processing.core.parsers.saml.SAMLAssertionParser;
import org.keycloak.saml.processing.core.saml.v2.common.SAMLDocumentHolder;
import org.keycloak.saml.processing.core.saml.v2.util.AssertionUtil;
import org.keycloak.saml.processing.core.saml.v2.util.DocumentUtil;
import org.keycloak.testsuite.rule.AbstractKeycloakRule;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.wildfly.elytron.web.undertow.server.ElytronContextAssociationHandler;
import org.wildfly.elytron.web.undertow.server.ElytronHttpExchange;
import org.wildfly.elytron.web.undertow.server.ScopeSessionListener;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.realm.token.TokenSecurityRealm;
import org.wildfly.security.auth.realm.token.TokenValidator;
import org.wildfly.security.auth.realm.token.validator.JwtValidator;
import org.wildfly.security.auth.server.HttpAuthenticationFactory;
import org.wildfly.security.auth.server.MechanismConfiguration;
import org.wildfly.security.auth.server.MechanismConfigurationSelector;
import org.wildfly.security.auth.server.MechanismRealmConfiguration;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.evidence.BearerTokenEvidence;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpScopeNotification;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.Scope;
import org.wildfly.security.http.util.FilterServerMechanismFactory;
import org.wildfly.security.http.util.ServiceLoaderServerMechanismFactory;
import org.wildfly.security.permission.PermissionVerifier;

import javax.servlet.Servlet;
import javax.servlet.ServletContext;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpSession;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public abstract class SamlKeycloakRule extends AbstractKeycloakRule {

    public static class TestResourceManager implements ResourceManager {

        private final String basePath;

        public TestResourceManager(String basePath){
            this.basePath = basePath;
        }

        @Override
        public Resource getResource(String path) throws IOException {
            String temp = path;
            String fullPath = basePath + temp;
            URL url = getClass().getResource(fullPath);
            if (url == null) {
                System.out.println("url is null: " + fullPath);
            }
            return new URLResource(url, url.openConnection(), path);
        }

        @Override
        public boolean isResourceChangeListenerSupported() {
            throw new RuntimeException();
        }

        @Override
        public void registerResourceChangeListener(ResourceChangeListener listener) {
            throw new RuntimeException();
        }

        @Override
        public void removeResourceChangeListener(ResourceChangeListener listener) {
            throw new RuntimeException();
        }

        @Override
        public void close() throws IOException {
            throw new RuntimeException();
        }
    }

    public static class TestIdentityManager implements IdentityManager {
        @Override
        public Account verify(Account account) {
            return account;
        }

        @Override
        public Account verify(String userName, Credential credential) {
            throw new RuntimeException("WTF");
        }

        @Override
        public Account verify(Credential credential) {
            throw new RuntimeException();
        }
    }

    @Override
    protected void setupKeycloak() {
        String realmJson = getRealmJson();
        server.importRealm(getClass().getResourceAsStream(realmJson));
        initWars();
    }

    public abstract void initWars();

    public void initializeSamlSecuredWar(String warResourcePath, String contextPath, String warDeploymentName, ClassLoader classLoader) {

        Class<SendUsernameServlet> servletClass = SendUsernameServlet.class;
        String constraintUrl = "/*";

        initializeSamlSecuredWar(warResourcePath, contextPath, warDeploymentName, classLoader, servletClass, constraintUrl);
    }

    public void initializeSamlSecuredWar(String warResourcePath, String contextPath, String warDeploymentName, ClassLoader classLoader, Class<? extends Servlet> servletClass, String constraintUrl) {
        ServletInfo regularServletInfo = new ServletInfo("servlet", servletClass)
                .addMapping("/*");

        SecurityConstraint constraint = new SecurityConstraint();
        WebResourceCollection collection = new WebResourceCollection();
        collection.addUrlPattern(constraintUrl);
        constraint.addWebResourceCollection(collection);
        constraint.addRoleAllowed("manager");
        constraint.addRoleAllowed("el-jefe");
        LoginConfig loginConfig = new LoginConfig("KEYCLOAK-SAML", "Test Realm");

        ResourceManager resourceManager = new TestResourceManager(warResourcePath);

        DeploymentInfo deploymentInfo = new DeploymentInfo()
                .setClassLoader(classLoader)
                .setIdentityManager(new TestIdentityManager())
                .setContextPath(contextPath)
                .setDeploymentName(warDeploymentName)
                .setLoginConfig(loginConfig)
                .setResourceManager(resourceManager)
                .addServlets(regularServletInfo)
                .addSecurityConstraint(constraint);

        configureElytronSecurity(deploymentInfo);

        addErrorPage("/error.html", deploymentInfo);
        server.getServer().deploy(deploymentInfo);
    }

    public String getRealmJson() {
        return "/keycloak-saml/testsaml.json";
    }


    private void configureElytronSecurity(DeploymentInfo deploymentInfo) {
        Function<HttpServerExchange, SessionConfig> sessionConfigProvider = exchange -> {
            ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
            return servletRequestContext.getCurrentServletContext().getSessionConfig();
        };
        Function<HttpServerExchange, SessionManager> sessionManagerProvider = exchange -> {
            ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
            return servletRequestContext.getDeployment().getSessionManager();
        };
        ScopeSessionListener elytronNotificationListener = ScopeSessionListener.builder()
                .addScopeResolver(Scope.APPLICATION, SamlKeycloakRule::applicationScope)
                .build();

        deploymentInfo.addSessionListener(elytronNotificationListener);

        SecurityDomain.Builder builder = SecurityDomain.builder().setDefaultRealmName("default");

        SecurityDomain domain = builder
                .setPermissionMapper((permissionMappable, roles) -> PermissionVerifier.from(LoginPermission.getInstance()))
                .addRealm("default", TokenSecurityRealm.builder().principalClaimName("preferred_username").validator(new TokenValidator() {
                    @Override
                    public Attributes validate(BearerTokenEvidence evidence) throws RealmUnavailableException {
                        AssertionType assertion = null;
                        try {
                            Document document = DocumentUtil.getDocument(evidence.getToken());
                            assertion = new SAMLAssertionParser().fromElement(document.getDocumentElement());
                        } catch (ConfigurationException e) {
                            e.printStackTrace();
                        } catch (ProcessingException e) {
                            e.printStackTrace();
                        } catch (ParsingException e) {
                            e.printStackTrace();
                        }
                        SubjectType subject = assertion.getSubject();
                        SubjectType.STSubType subType = subject.getSubType();
                        NameIDType subjectNameID = (NameIDType) subType.getBaseID();
                        String principalName = subjectNameID.getValue();

                        final Set<String> roles = new HashSet<>();
                        MultivaluedHashMap<String, String> attributes = new MultivaluedHashMap<>();
                        MultivaluedHashMap<String, String> friendlyAttributes = new MultivaluedHashMap<>();

                        Set<StatementAbstractType> statements = assertion.getStatements();
                        for (StatementAbstractType statement : statements) {
                            if (statement instanceof AttributeStatementType) {
                                AttributeStatementType attributeStatement = (AttributeStatementType) statement;
                                List<AttributeStatementType.ASTChoiceType> attList = attributeStatement.getAttributes();
                                for (AttributeStatementType.ASTChoiceType obj : attList) {
                                    AttributeType attr = obj.getAttribute();
                                    if (isRole(attr)) {
                                        List<Object> attributeValues = attr.getAttributeValue();
                                        if (attributeValues != null) {
                                            for (Object attrValue : attributeValues) {
                                                String role = getAttributeValue(attrValue);
                                                roles.add(role);
                                            }
                                        }
                                    } else {
                                        List<Object> attributeValues = attr.getAttributeValue();
                                        if (attributeValues != null) {
                                            for (Object attrValue : attributeValues) {
                                                String value = getAttributeValue(attrValue);
                                                if (attr.getName() != null) {
                                                    attributes.add(attr.getName(), value);
                                                }
                                                if (attr.getFriendlyName() != null) {
                                                    friendlyAttributes.add(attr.getFriendlyName(), value);
                                                }
                                            }
                                        }
                                    }

                                }
                            }
                        }

                        Attributes attributes1 = new MapAttributes(attributes);

                        attributes1.addFirst("preferred_username", principalName);
                        attributes1.addAll("Roles", roles);

                        return attributes1;
                    }

                    protected boolean isRole(AttributeType attribute) {
                        List<String> roleNames = Arrays.asList("role", "Role");
                        return (attribute.getName() != null && roleNames.contains(attribute.getName())) || (attribute.getFriendlyName() != null && roleNames.contains(attribute.getFriendlyName()));
                    }

                    private String getAttributeValue(Object attrValue) {
                        String value = null;
                        if (attrValue instanceof String) {
                            value = (String) attrValue;
                        } else if (attrValue instanceof Node) {
                            Node roleNode = (Node) attrValue;
                            value = roleNode.getFirstChild().getNodeValue();
                        } else if (attrValue instanceof NameIDType) {
                            NameIDType nameIdType = (NameIDType) attrValue;
                            value = nameIdType.getValue();
                        } else {
                            throw new RuntimeException("Unable to extract unknown SAML assertion attribute value type: " + attrValue.getClass().getName());
                        }
                        return value;
                    }
                }).build())
                .setRoleDecoder(RoleDecoder.DEFAULT)
                .build().build();

        HttpAuthenticationFactory httpAuthenticationFactory = HttpAuthenticationFactory.builder()
                .setFactory(new FilterServerMechanismFactory(new ServiceLoaderServerMechanismFactory(getClass().getClassLoader()), false, "SPNEGO"))
                .setSecurityDomain(domain)
                .setMechanismConfigurationSelector(MechanismConfigurationSelector.constantSelector(
                        MechanismConfiguration.builder()
                                .addMechanismRealm(MechanismRealmConfiguration.builder().setRealmName("Elytron Realm").build())
                                .build()))
                .build();

        Map<Scope, Function<HttpServerExchange, HttpScope>> scopeResolvers = new HashMap<>();

        scopeResolvers.put(Scope.APPLICATION, new Function<HttpServerExchange, HttpScope>() {
            @Override
            public HttpScope apply(HttpServerExchange httpServerExchange) {
                return applicationScope(httpServerExchange);
            }
        });
        scopeResolvers.put(Scope.EXCHANGE, new Function<HttpServerExchange, HttpScope>() {
            @Override
            public HttpScope apply(HttpServerExchange httpServerExchange) {
                return requestScope(httpServerExchange);
            }
        });

        deploymentInfo.setInitialSecurityWrapper(handler -> ElytronContextAssociationHandler.builder()
                .setNext(handler)
                .setSecurityDomain(httpAuthenticationFactory.getSecurityDomain())
                .setHttpExchangeSupplier(httpServerExchange -> new ElytronHttpExchange(httpServerExchange, scopeResolvers, elytronNotificationListener) {
                    @Override
                    protected SessionManager getSessionManager() {
                        ServletRequestContext servletRequestContext = httpServerExchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
                        return servletRequestContext.getDeployment().getSessionManager();
                    }

                    @Override
                    protected SessionConfig getSessionConfig() {
                        ServletRequestContext servletRequestContext = httpServerExchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
                        return servletRequestContext.getCurrentServletContext().getSessionConfig();
                    }

                    @Override
                    public boolean suspendRequest() {
                        HttpScope scope = getScope(Scope.SESSION);

                        SavedRequest.trySaveRequest(httpServerExchange);

                        return scope.getAttachment(SavedRequest.class.getName()) != null;
                    }

                    @Override
                    public boolean resumeRequest() {
                        HttpScope scope = getScope(Scope.SESSION);
                        Object attachment = scope.getAttachment(SavedRequest.class.getName());
                        final ServletRequestContext servletRequestContext = httpServerExchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
                        HttpSession session = servletRequestContext.getCurrentServletContext().getSession(httpServerExchange, false);

                        if (session != null) {
                            SavedRequest.tryRestoreRequest(httpServerExchange, session);
                        }

                        return attachment != null && scope.getAttachment(SavedRequest.class.getName()) == null;
                    }
                })
                .setMechanismSupplier(() -> {
                    LoginConfig loginConfig = deploymentInfo.getLoginConfig();
                    if (loginConfig == null) {
                        return Collections.emptyList();
                    }
                    List<AuthMethodConfig> authMethods = loginConfig.getAuthMethods();

                    return httpAuthenticationFactory.getMechanismNames().stream().filter(s -> authMethods.stream().anyMatch(authMethodConfig -> authMethodConfig.getName().equals(s))).map(new Function<String, HttpServerAuthenticationMechanism>() {
                        @Override
                        public HttpServerAuthenticationMechanism apply(String s) {
                            try {
                                return httpAuthenticationFactory.createMechanism(s);
                            } catch (HttpAuthenticationException e) {
                                throw new RuntimeException(e);
                            }
                        }
                    }).collect(Collectors.toList());
                })
                .build());

        deploymentInfo.addListener(new ListenerInfo(KeycloakConfigurationServletListener.class));
    }

    private static HttpScope sessionScope(HttpServerExchange exchange, ScopeSessionListener listener) {
        return new HttpScope() {
            Session session = getSessionManager().getSession(exchange, getSessionConfig());
            protected SessionManager getSessionManager() {
                ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
                return servletRequestContext.getDeployment().getSessionManager();
            }

            protected SessionConfig getSessionConfig() {
                ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
                return servletRequestContext.getCurrentServletContext().getSessionConfig();
            }
            @Override
            public String getID() {
                return (session != null) ? session.getId() : null;
            }

            @Override
            public boolean exists() {
                return this.session != null;
            }

            @Override
            public synchronized boolean create() {
                if (session == null) {
                    session = getSessionManager().createSession(exchange, getSessionConfig());
                }
                return true;
            }

            @Override
            public boolean supportsAttachments() {
                return this.exists();
            }

            @Override
            public void setAttachment(String key, Object value) {
                if (session != null) {
                    session.setAttribute(key, value);
                }
            }

            @Override
            public Object getAttachment(String key) {
                return (session != null) ? session.getAttribute(key) : null;
            }

            @Override
            public boolean supportsInvalidation() {
                return this.exists();
            }

            @Override
            public boolean invalidate() {
                if (session != null) {
                    try {
                        session.invalidate(exchange);
                    } catch (Exception e) {}
                }
                return true;
            }

            @Override
            public boolean supportsNotifications() {
                return this.exists();
            }

            @Override
            public void registerForNotification(Consumer<HttpScopeNotification> consumer) {
                if (session != null) {
                    listener.registerListener(session.getId(), consumer);
                }
            }
        };
    }

    private static HttpScope applicationScope(HttpServerExchange exchange) {
        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);

        if (servletRequestContext != null) {
            final Deployment deployment = servletRequestContext.getDeployment();
            final ServletContext servletContext = deployment.getServletContext();
            return new HttpScope() {
                @Override
                public String getID() {
                    return deployment.getDeploymentInfo().getDeploymentName();
                }

                @Override
                public boolean supportsAttachments() {
                    return true;
                }

                @Override
                public void setAttachment(String key, Object value) {
                    servletContext.setAttribute(key, value);
                }

                @Override
                public Object getAttachment(String key) {
                    return servletContext.getAttribute(key);
                }

                @Override
                public boolean supportsResources() {
                    return true;
                }

                @Override
                public InputStream getResource(String path) {
                    return servletContext.getResourceAsStream(path);
                }
            };
        }

        return null;
    }

    private static HttpScope requestScope(HttpServerExchange exchange) {
        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);

        if (servletRequestContext != null) {
            final ServletRequest servletRequest = servletRequestContext.getServletRequest();
            return new HttpScope() {
                @Override
                public boolean supportsAttachments() {
                    return true;
                }

                @Override
                public void setAttachment(String key, Object value) {
                    servletRequest.setAttribute(key, value);
                }

                @Override
                public Object getAttachment(String key) {
                    return servletRequest.getAttribute(key);
                }

            };
        }

        return null;
    }
}
