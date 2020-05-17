package org.keycloak.quarkus.runtime;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLClassLoader;
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
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.keycloak.connections.liquibase.FastServiceLocator;
import org.keycloak.connections.liquibase.KeycloakLogger;
import org.keycloak.provider.KeycloakDeploymentInfo;
import org.keycloak.provider.ProviderManager;

import io.quarkus.agroal.runtime.DataSourceSupport;
import io.quarkus.arc.runtime.BeanContainer;
import io.quarkus.arc.runtime.BeanContainerListener;
import io.quarkus.datasource.common.runtime.DataSourceUtil;
import io.quarkus.runtime.annotations.Recorder;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigProviderResolver;
import liquibase.logging.LogFactory;
import liquibase.servicelocator.ServiceLocator;

@Recorder
public class KeycloakRecorder {
    public static final SmallRyeConfig CONFIG;

    static {
        CONFIG = (SmallRyeConfig) SmallRyeConfigProviderResolver.instance().getConfig();
    }

    public static KeycloakDeploymentInfo getKeycloakProviderDeploymentInfo(String name,
            List<String> paths) {
        KeycloakDeploymentInfo info = KeycloakDeploymentInfo.create().name(name);

        for (String path : paths) {
            try {
                File file = Paths.get(path).toFile();

                if (file.isFile()) {
                    URI jarUri = URI.create("jar:file:" + file.getAbsolutePath());
                    try (FileSystem zipfs = FileSystems.newFileSystem(jarUri, Collections.emptyMap())) {
                        Files.walkFileTree(zipfs.getPath("/"), new FileVisitor<Path>() {
                            @Override
                            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs)
                                    throws IOException {
                                return FileVisitResult.CONTINUE;
                            }

                            @Override
                            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                                if (file.toAbsolutePath().toString().contains("META-INF/keycloak-themes.json")) {
                                    info.themes();
                                }

                                if (file.toAbsolutePath().toString().contains("theme-resources")) {
                                    info.themeResources();
                                }

                                if (file.toAbsolutePath().toString().contains("META-INF/services/org.keycloak")) {
                                    info.name(jarUri.toString());
                                    info.services();
                                }
                                return FileVisitResult.CONTINUE;
                            }

                            @Override
                            public FileVisitResult visitFileFailed(Path file, IOException exc) throws IOException {
                                return FileVisitResult.CONTINUE;
                            }

                            @Override
                            public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                                return FileVisitResult.CONTINUE;
                            }
                        });
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        return info;
    }
    public static ClassLoader CLASS_LOADER;
    public static List<ProviderManager> PROVIDERS = new ArrayList();

    public void configureLiquibase(Map<String, List<String>> services) {
        LogFactory.setInstance(new LogFactory() {
            KeycloakLogger logger = new KeycloakLogger();

            @Override
            public liquibase.logging.Logger getLog(String name) {
                return logger;
            }

            @Override
            public liquibase.logging.Logger getLog() {
                return logger;
            }
        });
        ServiceLocator.setInstance(new FastServiceLocator(services));
    }

    public void configureUserProviders(List<String> paths) {
        for (String path : paths) {
            KeycloakDeploymentInfo info = getKeycloakProviderDeploymentInfo(UUID.randomUUID().toString(), paths);
            String name = info.getName();
            ProviderManager pm = null;
            try {
                CLASS_LOADER = new URLClassLoader(new URL[] { new File(path).toURL() },
                        CLASS_LOADER == null ? Thread.currentThread().getContextClassLoader() : CLASS_LOADER) {
                    @Override
                    public Enumeration<URL> getResources(String name) throws IOException {
                        List<URL> urls = new ArrayList<>();
                        Enumeration<URL> resources = super.getResources(name);

                        while (resources.hasMoreElements()) {
                            URL url = resources.nextElement();
                            if (url.toString().contains("jar")) {
                                urls.add(url);
                            }
                        }

                        return Collections.enumeration(urls);
                    }
                };
                pm = new ProviderManager(info, CLASS_LOADER);
            } catch (MalformedURLException e) {
                throw new RuntimeException(e);
            }
            CLASS_LOADER = CLASS_LOADER == null ? Thread.currentThread().getContextClassLoader() : CLASS_LOADER;
            PROVIDERS.add(pm);
        }
    }

    public BeanContainerListener configureDataSource() {
        return new BeanContainerListener() {
            @Override
            public void created(BeanContainer container) {
                String driver = CONFIG.getRawValue("quarkus.datasource.driver");
                DataSourceSupport instance = container.instance(DataSourceSupport.class);
                DataSourceSupport.Entry entry = instance.entries.get(DataSourceUtil.DEFAULT_DATASOURCE_NAME);
                entry.resolvedDriverClass = driver;
            }
        };
    }
}
