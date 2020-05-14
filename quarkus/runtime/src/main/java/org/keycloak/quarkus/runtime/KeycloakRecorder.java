package org.keycloak.quarkus.runtime;

import javax.xml.parsers.SAXParserFactory;
import java.lang.reflect.Method;
import java.sql.Connection;
import java.util.List;
import java.util.Map;

import io.agroal.api.AgroalDataSource;
import io.quarkus.arc.Arc;
import io.quarkus.arc.runtime.BeanContainer;
import io.quarkus.arc.runtime.BeanContainerListener;
import io.quarkus.runtime.RuntimeValue;
import io.quarkus.runtime.annotations.Recorder;
import liquibase.database.Database;
import liquibase.database.DatabaseFactory;
import liquibase.database.core.MariaDBDatabase;
import liquibase.database.core.MySQLDatabase;
import liquibase.database.core.PostgresDatabase;
import liquibase.database.jvm.JdbcConnection;
import liquibase.datatype.DataTypeFactory;
import liquibase.logging.LogFactory;
import liquibase.parser.ChangeLogParser;
import liquibase.parser.ChangeLogParserFactory;
import liquibase.parser.core.xml.XMLChangeLogSAXParser;
import liquibase.servicelocator.ServiceLocator;
import org.eclipse.microprofile.config.spi.ConfigSourceProvider;
import org.keycloak.connections.jpa.updater.liquibase.MySQL8VarcharType;
import org.keycloak.connections.jpa.updater.liquibase.PostgresPlusDatabase;
import org.keycloak.connections.jpa.updater.liquibase.UpdatedMariaDBDatabase;
import org.keycloak.connections.jpa.updater.liquibase.UpdatedMySqlDatabase;
import org.keycloak.connections.liquibase.FastServiceLocator;
import org.keycloak.connections.liquibase.KeycloakLogger;
import org.keycloak.provider.quarkus.KeycloakConfigSourceProvider;

@Recorder
public class KeycloakRecorder {
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

    public RuntimeValue<ConfigSourceProvider> loadConfiguration() {
        return new RuntimeValue<>(new KeycloakConfigSourceProvider());
    }

    public BeanContainerListener configureDatabase() {
        return new BeanContainerListener() {
            @Override
            public void created(BeanContainer beanContainer) {
                AgroalDataSource dataSource = beanContainer.instance(AgroalDataSource.class);

                try (Connection connection = dataSource.getConnection()) {
                    Database database = DatabaseFactory.getInstance()
                            .findCorrectDatabaseImplementation(new JdbcConnection(connection));
                    DatabaseFactory.getInstance().clearRegistry();
                    if (database.getDatabaseProductName().equals(PostgresDatabase.PRODUCT_NAME)) {
                        // Adding PostgresPlus support to liquibase
                        DatabaseFactory.getInstance().register(new PostgresPlusDatabase());
                    } else if (database.getDatabaseProductName().equals(MySQLDatabase.PRODUCT_NAME)) {
                        // Adding newer version of MySQL/MariaDB support to liquibase
                        DatabaseFactory.getInstance().register(new UpdatedMySqlDatabase());
                        // Adding CustomVarcharType for MySQL 8 and newer
                        DataTypeFactory.getInstance().register(MySQL8VarcharType.class);
                    } else if (database.getDatabaseProductName().equals(MariaDBDatabase.PRODUCT_NAME)) {
                        DatabaseFactory.getInstance().register(new UpdatedMariaDBDatabase());
                        // Adding CustomVarcharType for MySQL 8 and newer
                        DataTypeFactory.getInstance().register(MySQL8VarcharType.class);
                    } else {
                        DatabaseFactory.getInstance().register(database);
                    }

                    FastServiceLocator.class.cast(ServiceLocator.getInstance()).register(database.getClass());

                    // disables XML validation
                    for (ChangeLogParser parser : ChangeLogParserFactory.getInstance().getParsers()) {
                        if (parser instanceof XMLChangeLogSAXParser) {
                            Method getSaxParserFactory = null;
                            try {
                                getSaxParserFactory = XMLChangeLogSAXParser.class.getDeclaredMethod("getSaxParserFactory");
                                getSaxParserFactory.setAccessible(true);
                                SAXParserFactory saxParserFactory = (SAXParserFactory) getSaxParserFactory.invoke(parser);
                                saxParserFactory.setValidating(false);
                            } catch (Exception e) {
                            } finally {
                                if (getSaxParserFactory != null) {
                                    getSaxParserFactory.setAccessible(false);
                                }
                            }
                        }
                    }
                } catch (Exception cause) {
                    throw new RuntimeException("Failed to configure Liquibase database", cause);
                }
            }
        };
    }
}
