package test.org.keycloak.quarkus;

import io.restassured.RestAssured;
import org.hamcrest.Matchers;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;

public class TestStartup {

    @RegisterExtension
    static final QuarkusUnitTest test = new QuarkusUnitTest()
            .setArchiveProducer(() -> ShrinkWrap.create(JavaArchive.class)
                    .addClasses(NoopResource.class)
                    .addAsResource("application.properties", "application.properties")
                    .addAsResource("keycloak.properties", "META-INF/keycloak.properties"));

    @Test
    public void testWelcomePage() {
//        RestAssured.given()
//                .when().get("/")
//                .then()
//                .statusCode(200)
//                .body(Matchers.containsString("Please create an initial admin user to get started"));
        try {
            Thread.sleep(1000000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
