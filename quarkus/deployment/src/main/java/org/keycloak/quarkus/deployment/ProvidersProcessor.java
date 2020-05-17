package org.keycloak.quarkus.deployment;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.FileVisitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;

import org.keycloak.quarkus.runtime.KeycloakRecorder;

import io.quarkus.bootstrap.model.PathsCollection;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.AdditionalApplicationArchiveBuildItem;

class ProvidersProcessor {

    @Record(ExecutionTime.RUNTIME_INIT)
    @BuildStep
    void configure(KeycloakRecorder recorder, BuildProducer<AdditionalApplicationArchiveBuildItem> providers) {
        Path providerPath = Paths
                .get(System.getProperty("user.home") + File.separator + ".keycloak" + File.separator + "providers");
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
                        providers.produce(
                                new AdditionalApplicationArchiveBuildItem(PathsCollection.builder().add(path).build()));
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
