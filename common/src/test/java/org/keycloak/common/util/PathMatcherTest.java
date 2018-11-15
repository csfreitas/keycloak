package org.keycloak.common.util;

import java.util.Arrays;
import java.util.Collection;
import org.junit.Assert;
import org.junit.Test;

/**
 *
 * @author Tomasz Prętki <tomasz.pretki@dgt.eu>
 */
public class PathMatcherTest {

    @Test
    public void testResourceOverloading() {
        final String otherTemplate = "/resource/{version}/subresource/{id}/{other}";
        final String entitiesTemplate = "/resource/{version}/subresource/{id}/entities";
        final PathMatcher<String> instance = new PathMatcher<String>() {
            @Override
            protected String getPath(final String entry) {
                return entry;
            }

            @Override
            protected Collection<String> getPaths() {
                return Arrays.asList(otherTemplate, entitiesTemplate);
            }
        };
        Assert.assertEquals(otherTemplate, instance.matches("/resource/v1/subresource/0/other"));
        Assert.assertEquals(entitiesTemplate, instance.matches("/resource/v1/subresource/0/entities"));
    }
}
