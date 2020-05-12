package org.keycloak.connections.jpa;

import javax.enterprise.inject.Instance;
import javax.enterprise.inject.spi.CDI;
import javax.persistence.EntityManagerFactory;

public class QuarkusEntityManagerFactoryProvider implements EntityManagerFactoryProvider{

    @Override
    public EntityManagerFactory getEntityManagerFactory() {
        Instance<EntityManagerFactory> instance = CDI.current().select(EntityManagerFactory.class);
        
        if (instance.isResolvable()) {
            return instance.get();
        }
        
        throw new RuntimeException("Failed to resolve " + EntityManagerFactory.class + " from Quarkus runtime");
    }
}
