/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.authorization.jpa.store;

import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.jpa.entities.PermissionTicketEntity;
import org.keycloak.authorization.jpa.entities.PolicyEntity;
import org.keycloak.authorization.jpa.entities.ResourceEntity;
import org.keycloak.authorization.jpa.entities.ResourceServerEntity;
import org.keycloak.authorization.jpa.entities.ScopeEntity;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.store.ResourceServerStore;
import org.keycloak.models.ModelException;
import org.keycloak.storage.StorageId;

import javax.persistence.EntityManager;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaDelete;
import javax.persistence.criteria.Root;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class JPAResourceServerStore implements ResourceServerStore {

    private final EntityManager entityManager;
    private final AuthorizationProvider provider;

    public JPAResourceServerStore(EntityManager entityManager, AuthorizationProvider provider) {
        this.entityManager = entityManager;
        this.provider = provider;
    }

    @Override
    public ResourceServer create(String clientId) {
        if (!StorageId.isLocalStorage(clientId)) {
            throw new ModelException("Creating resource server from federated ClientModel not supported");
        }
        ResourceServerEntity entity = new ResourceServerEntity();

        entity.setId(clientId);

        this.entityManager.persist(entity);

        return new ResourceServerAdapter(entity, entityManager, provider.getStoreFactory());
    }

    @Override
    public void delete(String id) {
        ResourceServerEntity entity = entityManager.find(ResourceServerEntity.class, id);
        if (entity == null) return;

        delete(PolicyEntity.class, entity);
        delete(PermissionTicketEntity.class, entity);
        delete(ResourceEntity.class, entity);
        delete(ScopeEntity.class, entity);

        this.entityManager.remove(entity);
        entityManager.flush();
        entityManager.detach(entity);
    }

    @Override
    public ResourceServer findById(String id) {
        ResourceServerEntity entity = entityManager.find(ResourceServerEntity.class, id);
        if (entity == null) return null;
        return new ResourceServerAdapter(entity, entityManager, provider.getStoreFactory());
    }

    private void delete(Class type, ResourceServerEntity entity) {
        CriteriaBuilder criteriaBuilder = entityManager.getCriteriaBuilder();
        CriteriaDelete criteriaDelete = criteriaBuilder.createCriteriaDelete(type);
        Root from = criteriaDelete.from(type);

        criteriaDelete.where(criteriaBuilder.equal(from.get("resourceServer").get("id"), entity.getId()));

        entityManager.createQuery(criteriaDelete).executeUpdate();
    }
}
