package org.keycloak.connections.jpa;

import javax.persistence.EntityManagerFactory;

public interface EntityManagerFactoryProvider {

    EntityManagerFactory getEntityManagerFactory();
}
