package org.keycloak.validation;

import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.oidc.OIDCClientRepresentation;
import org.keycloak.validate.ValidationContext;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ClientValidationContext extends ValidationContext {



    enum Event {
        CREATE,
        UPDATE;
    }
    private final Event event;

    private final ClientModel client;
    public ClientValidationContext(Event event, KeycloakSession session, ClientModel client) {
        super(session);
        this.event = event;
        this.client = client;
    }

    public ClientModel getClient() {
        return client;
    }

    public static class OIDCContext extends ClientValidationContext{

        private final OIDCClientRepresentation oidcClient;

        public OIDCContext(Event event, KeycloakSession session, ClientModel client,
                OIDCClientRepresentation oidcClient) {
            super(event, session, client);
            this.oidcClient = oidcClient;
        }

        public OIDCClientRepresentation getOIDCClient() {
            return oidcClient;
        }
    }
}
