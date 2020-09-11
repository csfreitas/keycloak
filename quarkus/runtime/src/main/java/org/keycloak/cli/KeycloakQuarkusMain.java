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

package org.keycloak.cli;

import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.keycloak.common.Version;
import org.keycloak.util.Environment;

import io.quarkus.runtime.Quarkus;
import io.quarkus.runtime.annotations.QuarkusMain;
import picocli.CommandLine;

@QuarkusMain(name = "keycloak")
public class KeycloakQuarkusMain {

    public static void main(String args[]) {
        System.setProperty("kc.version", Version.VERSION_KEYCLOAK);

        if (args.length != 0) {
            CommandLine.Model.CommandSpec spec = CommandLine.Model.CommandSpec.forAnnotatedObject(new MainCommand())
                    .name(Environment.getCommand());

            CommandLine cmd = new CommandLine(spec);
            boolean hasSubcommand;
            List<String> argsList = new LinkedList<>(Arrays.asList(args));

            try {
                hasSubcommand = cmd.parseArgs(args).hasSubcommand();
            } catch (CommandLine.UnmatchedArgumentException e) {
                // handle any unmatched option as possible configuration options that should be passed to Keycloak making possible
                // to pass options not supported by the CLI
                // TODO: we should change the Provider SPI to advertise the options supported by each provider
                System.setProperty("kc.config.args", parseUnmatchedOptions(argsList, e));
                hasSubcommand = cmd.parseArgs(argsList.toArray(new String[argsList.size()])).hasSubcommand();
            }

            if (!hasSubcommand) {
                argsList.add("start");
            }

            int exitCode = cmd.execute(argsList.toArray(new String[argsList.size()]));

            if (exitCode != -1) {
                System.exit(exitCode);
            }
        }

        Quarkus.run(args);
        Quarkus.waitForExit();
    }

    private static String parseUnmatchedOptions(List<String> argsList, CommandLine.UnmatchedArgumentException e) {
        StringBuilder options = new StringBuilder();

        for (String unmatchedOption : e.getUnmatched()) {
            Iterator<String> iterator = argsList.iterator();

            while (iterator.hasNext()) {
                String key = iterator.next();

                if (unmatchedOption.equals(key)) {
                    if (options.length() > 0) {
                        options.append(",");
                    }

                    iterator.remove();

                    String value;
                    int keySeparator = key.indexOf('=');

                    if (iterator.hasNext() && keySeparator == -1) {
                        value = iterator.next();
                        iterator.remove();
                    } else {
                        if (keySeparator == -1) {
                            throw new IllegalArgumentException("Invalid value for option [" + key + "]");
                        }

                        value = key.substring(keySeparator + 1);

                        key = key.substring(0, keySeparator);
                    }

                    options.append(key).append("=").append(value);
                }
            }
        }

        return options.toString();
    }
}
