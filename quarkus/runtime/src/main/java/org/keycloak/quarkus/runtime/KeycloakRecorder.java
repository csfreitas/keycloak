package org.keycloak.quarkus.runtime;

import java.util.List;
import java.util.Map;

import io.quarkus.runtime.RuntimeValue;
import io.quarkus.runtime.annotations.Recorder;
import liquibase.servicelocator.ServiceLocator;
import org.eclipse.microprofile.config.spi.ConfigSourceProvider;
import org.keycloak.connections.liquibase.FastServiceLocator;
import org.keycloak.provider.quarkus.KeycloakConfigSourceProvider;

@Recorder
public class KeycloakRecorder {
    public void configureLiquibase(Map<String, List<String>> services) {
        ServiceLocator.setInstance(new FastServiceLocator(services));
    }

    public RuntimeValue<ConfigSourceProvider> loadConfiguration() {
        return new RuntimeValue<>(new KeycloakConfigSourceProvider());
    }
}
