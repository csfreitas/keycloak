/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.testsuite.user.profile.config;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.userprofile.UserProfileContext;

/**
 * Utility methods to work with User Profile Configurations
 * 
 * @author Vlastimil Elias <velias@redhat.com>
 *
 */
public class UPConfigUtils {

    /**
     * Break string to substrings of given length
     * 
     * @param src to break
     * @param partLength
     * @return list of string parts, never null (but can be empty if src is null)
     */
    public static List<String> breakString(String src, int partLength) {
        List<String> ret = new ArrayList<>();
        if (src != null) {
            int pieces = (src.length() / partLength) + 1;
            for (int i = 0; i < pieces; i++) {
                if ((i + 1) < pieces)
                    ret.add(src.substring(i * partLength, (i + 1) * partLength));
                else if (i == 0 || (i * partLength) < src.length())
                    ret.add(src.substring(i * partLength));
            }
        }

        return ret;
    }

    /**
     * Check if context CAN BE part of the AuthenticationFlow.
     * 
     * @param context to check
     * @return true if context CAN BE part of the auth flow
     */
    public static boolean canBeAuthFlowContext(UserProfileContext context) {
        return context != UserProfileContext.USER_API && context != UserProfileContext.ACCOUNT
                && context != UserProfileContext.ACCOUNT_OLD;
    }

    /**
     * Check if roles configuration contains role given current context.
     * 
     * @param context to be checked
     * @param roles to be inspected
     * @return true if roles list contains role representing checked context
     */
    public static boolean isRoleForContext(UserProfileContext context, List<String> roles) {
        if (roles == null)
            return false;
        if (context == UserProfileContext.USER_API)
            return roles.contains(UPConfigParser.ROLE_ADMIN);
        else
            return roles.contains(UPConfigParser.ROLE_USER);
    }

    public static String capitalizeFirstLetter(String str) {
        if (str == null || str.isEmpty())
            return str;
        return str.substring(0, 1).toUpperCase() + str.substring(1);
    }

}
