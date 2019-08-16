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

package org.keycloak.subsystem.server.extension;

import java.util.ArrayList;
import java.util.List;
import java.util.Stack;

import org.xml.sax.Attributes;
import org.xml.sax.helpers.DefaultHandler;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
final class ScriptProviderXmlParser extends DefaultHandler {

    private static final String SCRIPT_AUTHENTICATOR_PROVIDER = "script-authenticator-provider";
    private static final String JS_POLICY_PROVIDER = "js-policy-provider";
    private static final String PROVIDERS = "providers";

    private final Stack<ScriptProviderMetadata> stack = new Stack();
    private final List<ScriptProviderMetadata> providers = new ArrayList<>();

    @Override
    public void startElement(String uri, String localName, String qName, Attributes attributes) {
        if (PROVIDERS.equals(qName)) {
            return;
        }

        stack.push(createMetadata(qName, attributes));
    }

    @Override
    public void endElement(String uri, String localName, String qName) {
        if (stack.isEmpty()) {
            return;
        }
        providers.add(stack.pop());
    }

    @Override
    public void characters(char[] ch, int start, int length) {
        if (stack.isEmpty()) {
            return;
        }
        stack.peek().setCode(String.valueOf(ch, start, length));
    }

    private ScriptProviderMetadata createMetadata(String qName, Attributes attributes) {
        switch (qName) {
            case SCRIPT_AUTHENTICATOR_PROVIDER:
                return new ScriptAuthenticatorProviderMetadata(attributes.getValue("name"));
            case JS_POLICY_PROVIDER:
                return new JSPolicyProviderMetadata(attributes.getValue("name"));
            default:
                throw unexpectedElement(qName);
        }
    }

    private RuntimeException unexpectedElement(String localName) {
        return new RuntimeException("Unexpected element: " + localName);
    }

    List<ScriptProviderMetadata> getProviders() {
        return providers;
    }
}
