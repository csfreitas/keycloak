package org.keycloak.quarkus.deployment;

import org.keycloak.quarkus.runtime.KeycloakConfig;
import org.keycloak.quarkus.runtime.KeycloakRecorder;

import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.deployment.builditem.RunTimeConfigurationSourceValueBuildItem;

class KeycloakProcessor {

    @BuildStep
    FeatureBuildItem feature() {
        return new FeatureBuildItem("keycloak");
    }

    @Record(ExecutionTime.RUNTIME_INIT)
    @BuildStep
    RunTimeConfigurationSourceValueBuildItem loadConfiguration(KeycloakConfig config, KeycloakRecorder recorder) {
        return new RunTimeConfigurationSourceValueBuildItem(recorder.loadConfiguration());
    }
}
