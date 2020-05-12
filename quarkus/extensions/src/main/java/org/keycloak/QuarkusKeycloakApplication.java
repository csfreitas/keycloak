package org.keycloak;

import javax.inject.Inject;
import javax.persistence.EntityManagerFactory;
import javax.ws.rs.ApplicationPath;

import io.agroal.api.AgroalDataSource;
import org.keycloak.services.resources.KeycloakApplication;

@ApplicationPath("/")
public class QuarkusKeycloakApplication extends KeycloakApplication {

}
