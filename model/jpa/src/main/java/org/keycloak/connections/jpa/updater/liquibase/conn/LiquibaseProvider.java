package org.keycloak.connections.jpa.updater.liquibase.conn;

import liquibase.Liquibase;

public interface LiquibaseProvider {
    Liquibase getLiquibase();
}
