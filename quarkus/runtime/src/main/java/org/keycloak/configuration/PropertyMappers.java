/*
 * Copyright 202 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.configuration;

import static org.keycloak.configuration.PropertyMapper.create;
import static org.keycloak.configuration.PropertyMapper.createWithDefault;

import io.quarkus.runtime.configuration.ProfileManager;
import io.smallrye.config.ConfigSourceInterceptorContext;
import io.smallrye.config.ConfigValue;
import org.keycloak.quarkus.KeycloakRecorder;

/**
 * Configures the {@link PropertyMapper} instances for all Keycloak configuration properties that should be mapped to their
 * corresponding properties in Quarkus.
 */
final class PropertyMappers {

    static {
        configureDatabasePropertyMappers();
        configureHttpPropertyMappers();
    }

    private static void configureHttpPropertyMappers() {
        createWithDefault("http.enabled", "quarkus.http.insecure-requests", "disabled", s -> {
            Boolean enabled = Boolean.valueOf(s);
            
            if ("dev".equalsIgnoreCase(ProfileManager.getActiveProfile())) {
                enabled = true;
            }
            
            return enabled ? "enabled" : "disabled";
        });
        createWithDefault("http.port", "quarkus.http.port", String.valueOf(8080));
        createWithDefault("https.port", "quarkus.http.ssl-port", String.valueOf(8443));
        createWithDefault("https.client-auth", "quarkus.http.ssl.client-auth", "none");
        create("https.cipher-suites", "quarkus.http.ssl.cipher-suites");
        create("https.protocols", "quarkus.http.ssl.protocols");
        create("https.certificate.file", "quarkus.http.ssl.certificate.file");
        create("https.certificate.key-store-file", "quarkus.http.ssl.certificate.key-store-file");
        create("https.certificate.key-store-password", "quarkus.http.ssl.certificate.key-store-password");
        create("https.certificate.key-store-file-type", "quarkus.http.ssl.certificate.key-store-file-type");
        create("https.certificate.trust-store-file", "quarkus.http.ssl.certificate.trust-store-file");
        create("https.certificate.trust-store-password", "quarkus.http.ssl.certificate.trust-store-password");
        create("https.certificate.trust-store-file-type", "quarkus.http.ssl.certificate.trust-store-file-type");
    }

    private static void configureDatabasePropertyMappers() {
        create("database", "quarkus.hibernate-orm.dialect", from -> {
            switch (from.toLowerCase()) {
                case "h2-file":
                case "h2-mem":
                    return "io.quarkus.hibernate.orm.runtime.dialect.QuarkusH2Dialect";
                case "mariadb":
                    return "org.hibernate.dialect.MariaDBDialect";
                case "postgres-95":
                    return "io.quarkus.hibernate.orm.runtime.dialect.QuarkusPostgreSQL95Dialect";
                case "postgres-10":
                    return "io.quarkus.hibernate.orm.runtime.dialect.QuarkusPostgreSQL10Dialect";
            }
            return null;
        });
        create("database", "quarkus.datasource.driver", vendor -> {
            switch (vendor.toLowerCase()) {
                case "h2-file":
                case "h2-mem":
                    return "org.h2.jdbcx.JdbcDataSource";
                case "mariadb":
                    return "org.mariadb.jdbc.MySQLDataSource";
                case "postgres-95":
                case "postgres-10":
                    return "org.postgresql.xa.PGXADataSource";
            }
            return null;
        });
        create("database", "quarkus.datasource.jdbc.transactions", vendor -> "xa");
        create("database.url", "database", "quarkus.datasource.url", vendor -> {
            switch (vendor.toLowerCase()) {
                case "h2-file":
                    return "jdbc:h2:file:${kc.home.dir:${kc.database.url.path:~}}/data/keycloakdb${kc.database.url.properties:;;AUTO_SERVER=TRUE}";
                case "h2-mem":
                    return "jdbc:h2:mem:keycloakdb${kc.database.url.properties:}";
                case "mariadb":
                    return "jdbc:mariadb://${kc.database.url.host:localhost}/${kc.database.url.database:keycloak}${kc.database.url.properties:}";
                case "postgres-95":
                case "postgres-10":
                    return "jdbc:postgresql://${kc.database.url.host:localhost}/${kc.database.url.database}${kc.database.url.properties:}";
            }
            return null;
        });
        create("database.username", "quarkus.datasource.username");
        create("database.password", "quarkus.datasource.password");
        create("database.schema", "quarkus.datasource.schema");
        create("database.pool.initial-size", "quarkus.datasource.jdbc.initial-size");
        create("database.pool.min-size", "quarkus.datasource.jdbc.min-size");
        createWithDefault("database.pool.max-size", "quarkus.datasource.jdbc.max-size", String.valueOf(100));
    }

    static ConfigValue getValue(ConfigSourceInterceptorContext context, String name) {
        return PropertyMapper.MAPPERS.getOrDefault(name, PropertyMapper.IDENTITY)
                .getOrDefault(name, context, context.proceed(name));
    }
}
