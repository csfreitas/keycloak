package org.keycloak.quarkus.deployment;

import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.FeatureBuildItem;

class KeycloakProcessor {

    @BuildStep
    FeatureBuildItem feature() {
        return new FeatureBuildItem("keycloak");
    }
}
