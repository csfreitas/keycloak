package test.org.keycloak.quarkus;

import javax.inject.Inject;
import javax.persistence.EntityManagerFactory;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import org.keycloak.services.resources.WelcomeResource;

@Path("/noop")
public class NoopResource {

    @Inject
    EntityManagerFactory entityManagerFactory;

    @GET
    public Response noop() {
        return Response.seeOther(UriBuilder.fromResource(WelcomeResource.class).build()).build();
    }

}
