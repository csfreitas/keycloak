package org.keycloak.quarkus.deployment;

import java.util.Optional;

import io.quarkus.agroal.runtime.DataSourcesJdbcBuildTimeConfig;
import io.quarkus.agroal.runtime.LegacyDataSourcesJdbcBuildTimeConfig;
import io.quarkus.arc.deployment.BeanContainerListenerBuildItem;
import org.keycloak.quarkus.runtime.KeycloakRecorder;

import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.hibernate.orm.deployment.HibernateOrmConfig;

class KeycloakProcessor {

    @BuildStep
    FeatureBuildItem getFeature() {
        return new FeatureBuildItem("keycloak");
    }

    @Record(ExecutionTime.STATIC_INIT)
    @BuildStep
    void configureHibernate(KeycloakRecorder recorder, HibernateOrmConfig hibernateConfig, 
            LegacyDataSourcesJdbcBuildTimeConfig dd, DataSourcesJdbcBuildTimeConfig dsConfig) {
        String dialect = KeycloakRecorder.CONFIG.getRawValue("quarkus.datasource.dialect");
        hibernateConfig.dialect = Optional.of(dialect);
    }

    @Record(ExecutionTime.STATIC_INIT)
    @BuildStep
    void configureDataSource(KeycloakRecorder recorder, BuildProducer<BeanContainerListenerBuildItem> container) {
        container.produce(new BeanContainerListenerBuildItem(recorder.configureDataSource()));
    }
}
