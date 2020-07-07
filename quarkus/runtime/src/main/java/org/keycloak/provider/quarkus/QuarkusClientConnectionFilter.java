/*
 * Copyright 2019 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.provider.quarkus;

import org.keycloak.common.ClientConnection;
import org.keycloak.services.filters.AbstractRequestFilter;

import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;

/**
 * <p>This filter is responsible for managing the request lifecycle as well as setting up the necessary context to process incoming
 * requests.
 * 
 * <p>The filter itself runs in a event loop and should delegate to worker threads any blocking code (for now, all requests are handled
 * as blocking).
 */
public class QuarkusClientConnectionFilter extends AbstractRequestFilter implements Handler<RoutingContext> {

    private static final Handler<AsyncResult<Object>> EMPTY_RESULT = result -> {
        // we don't really care about the result because any exception thrown should be handled by the parent class
    };

    @Override
    public void handle(RoutingContext context) {
        ClientConnection clientConnection = createClientConnection(context.request());

        // our code should always be run as blocking until we don't provide a better support for running non-blocking code
        // in the event loop
        context.vertx().executeBlocking(promise -> filter(clientConnection, (session) -> {
            try {
                context.next();
                promise.complete();
            } catch (Exception cause) {
                promise.fail(cause);
                // re-throw so that the any exception is handled from parent
                throw new RuntimeException(cause);
            }
        }), EMPTY_RESULT);
    }

    private ClientConnection createClientConnection(HttpServerRequest request) {
        return new ClientConnection() {
            @Override
            public String getRemoteAddr() {
                return request.remoteAddress().host();
            }

            @Override
            public String getRemoteHost() {
                return request.remoteAddress().host();
            }

            @Override
            public int getRemotePort() {
                return request.remoteAddress().port();
            }

            @Override
            public String getLocalAddr() {
                return request.localAddress().host();
            }

            @Override
            public int getLocalPort() {
                return request.localAddress().port();
            }
        };
    }
}
