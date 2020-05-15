package org.keycloak.quarkus.deployment;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.FileVisitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.builditem.AdditionalApplicationArchiveBuildItem;
import org.keycloak.provider.KeycloakDeploymentInfo;
import org.keycloak.provider.ProviderManager;
import org.keycloak.provider.ProviderManagerRegistry;
import org.keycloak.quarkus.runtime.KeycloakRecorder;

import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.hibernate.orm.deployment.HibernateOrmConfig;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigProviderResolver;

class KeycloakProcessor {

    @BuildStep
    FeatureBuildItem feature() {
        return new FeatureBuildItem("keycloak");
    }

    @Record(ExecutionTime.STATIC_INIT)
    @BuildStep
    void configureHibernate(KeycloakRecorder recorder, HibernateOrmConfig hibernateConfig) {
        SmallRyeConfig config = (SmallRyeConfig) SmallRyeConfigProviderResolver.instance().getConfig();
        String driver = config.getRawValue("quarkus.datasource.dialect");
        hibernateConfig.dialect = Optional.of(driver);
    }

    @Record(ExecutionTime.RUNTIME_INIT)
    @BuildStep
    void configureHibernate(KeycloakRecorder recorder, BuildProducer<AdditionalApplicationArchiveBuildItem> providers) {
        Path providerPath = Paths.get(System.getProperty("user.home") + File.separator + ".keycloak" + File.separator + "providers");
        List<String> paths = new ArrayList<>();

        try {
            Files.walkFileTree(providerPath, new FileVisitor<Path>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path path, BasicFileAttributes attrs) throws IOException {
                    File file = path.toFile();

                    if (file.isFile()) {
                        paths.add(path.toAbsolutePath().toString());
                        providers.produce(new AdditionalApplicationArchiveBuildItem(path));
                    }

                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException exc) throws IOException {
                    return FileVisitResult.TERMINATE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            e.printStackTrace();
        }
        recorder.configureUserProviders(paths);
    }
}
