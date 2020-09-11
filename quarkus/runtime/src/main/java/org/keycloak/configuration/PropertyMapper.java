/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.configuration;

import static org.keycloak.configuration.MicroProfileConfigProvider.NS_KEYCLOAK_PREFIX;
import static org.keycloak.util.Environment.getBuiltTimeProperty;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import io.smallrye.config.ConfigSourceInterceptorContext;
import io.smallrye.config.ConfigValue;

class PropertyMapper {

    static PropertyMapper create(String fromProperty, String toProperty) {
        return MAPPERS.computeIfAbsent(toProperty, s -> new PropertyMapper(fromProperty, s, null, null));
    }

    static PropertyMapper createWithDefault(String fromProperty, String toProperty, String defaultValue) {
        return MAPPERS.computeIfAbsent(toProperty, s -> new PropertyMapper(fromProperty, s, defaultValue, null));
    }

    static PropertyMapper createWithDefault(String fromProperty, String toProperty, String defaultValue, Function<String, String> mapper) {
        return MAPPERS.computeIfAbsent(toProperty, s -> new PropertyMapper(fromProperty, s, defaultValue, mapper));
    }

    static PropertyMapper create(String fromProperty, String toProperty, Function<String, String> mapper) {
        return MAPPERS.computeIfAbsent(toProperty, s -> new PropertyMapper(fromProperty, s, null, mapper, null));
    }

    static PropertyMapper create(String fromProperty, String mapFrom, String toProperty, Function<String, String> mapper) {
        return MAPPERS.computeIfAbsent(toProperty, s -> new PropertyMapper(fromProperty, s, null, mapper, mapFrom));
    }

    static Map<String, PropertyMapper> MAPPERS = new HashMap<>();

    static PropertyMapper IDENTITY = new PropertyMapper(null, null, null, null) {
        @Override
        public ConfigValue getOrDefault(String name, ConfigSourceInterceptorContext context, ConfigValue current) {
            if (current == null) {
                ConfigValue.builder().withName(name)
                        .withValue(getBuiltTimeProperty(
                                NS_KEYCLOAK_PREFIX + name.substring(NS_KEYCLOAK_PREFIX.length()).replaceAll("\\.", "-"))
                                        .orElseGet(() -> getBuiltTimeProperty(name).orElse(null)))
                        .build();
            }

            return current;
        }
    };

    private final String to;
    private final String from;
    private final String defaultValue;
    private final Function<String, String> mapper;
    private final String mapFrom;

    PropertyMapper(String from, String to, String defaultValue, Function<String, String> mapper) {
        this(from, to, defaultValue, mapper, null);
    }

    PropertyMapper(String from, String to, String defaultValue, Function<String, String> mapper, String mapFrom) {
        this.from = MicroProfileConfigProvider.NS_KEYCLOAK_PREFIX + from;
        this.to = to;
        this.defaultValue = defaultValue;
        if (mapper == null) {
            this.mapper = Function.identity();
        } else {
            this.mapper = mapper;
        }
        this.mapFrom = mapFrom;
    }

    ConfigValue getOrDefault(String name, ConfigSourceInterceptorContext context, ConfigValue current) {
        Optional<ConfigValue> buildConfig = getBuiltTimeConfig(from);

        // if the property was already defined when configuring the server, we use the configuration
        // any attempt to override this configuration will fail and a new config run is needed
        if (buildConfig.isPresent()) {
            return buildConfig.get();
        }

        // try to obtain the value for the property we want to map
        ConfigValue config = context.proceed(from);

        if (config == null) {
            if (mapFrom != null) {
                // if the property we want to map depends on another one, we use the value from the other property to call the mapper
                String parentKey = MicroProfileConfigProvider.NS_KEYCLOAK + "." + mapFrom;
                ConfigValue parentValue = getBuiltTimeConfig(parentKey).orElseGet(() -> {
                    ConfigValue value = context.proceed(parentKey);
                    
                    if (value == null) {
                        return null;
                    }
                    
                    return transformValue(value.getValue());
                });

                if (parentValue != null) {
                    return parentValue;
                }
            }

            // if not defined, return the current value from the property as a default if the property is not explicitly set
            if (defaultValue == null
                    || (current != null && !current.getConfigSourceName().equalsIgnoreCase("default values"))) {
                return current;
            }

            return ConfigValue.builder().withName(to).withValue(defaultValue).build();
        }

        if (mapFrom != null) {
            return config;
        }

        ConfigValue value = transformValue(config.getValue());

        // we always fallback to the current value from the property we are mapping
        if (value == null) {
            return current;
        }

        return value;
    }

    public Optional<ConfigValue> getBuiltTimeConfig(String name) {
        ConfigValue value = transformValue(getBuiltTimeProperty(name).orElseGet(() -> getBuiltTimeProperty(
                NS_KEYCLOAK_PREFIX + name.substring(NS_KEYCLOAK_PREFIX.length()).replaceAll("\\.", "-")).orElse(null)));

        if (value == null) {
            return Optional.empty();
        }

        return Optional.of(value);
    }
    
    private ConfigValue transformValue(String value) {
        if (value == null) {
            return null;
        }

        if (mapper == null) {
            return ConfigValue.builder().withName(to).withValue(value).build();
        }

        String mappedValue = mapper.apply(value);

        if (mappedValue != null) {
            return ConfigValue.builder().withName(to).withValue(mappedValue).build();
        }

        return null;
    }
}
