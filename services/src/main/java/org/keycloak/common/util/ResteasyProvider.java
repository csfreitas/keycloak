package org.keycloak.common.util;

public interface ResteasyProvider {

    <R> R getContextData(Class<R> type);

    void pushContext(Class type, Object instance);

    void clearContextData();

}
