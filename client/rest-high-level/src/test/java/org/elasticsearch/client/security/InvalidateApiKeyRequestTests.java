/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.client.security;

import org.elasticsearch.client.ValidationException;
import org.elasticsearch.test.ESTestCase;

import java.io.IOException;
import java.util.Optional;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;

public class InvalidateApiKeyRequestTests extends ESTestCase {

    public void testRequestValidation() {
        InvalidateApiKeyRequest request = InvalidateApiKeyRequest.usingApiKeyId(randomAlphaOfLength(5));
        Optional<ValidationException> ve = request.validate();
        assertThat(ve.isPresent(), is(false));
        request = InvalidateApiKeyRequest.usingApiKeyName(randomAlphaOfLength(5));
        ve = request.validate();
        assertThat(ve.isPresent(), is(false));
        request = InvalidateApiKeyRequest.usingRealmName(randomAlphaOfLength(5));
        ve = request.validate();
        assertThat(ve.isPresent(), is(false));
        request = InvalidateApiKeyRequest.usingUserName(randomAlphaOfLength(5));
        ve = request.validate();
        assertThat(ve.isPresent(), is(false));
        request = InvalidateApiKeyRequest.usingRealmAndUserName(randomAlphaOfLength(5), randomAlphaOfLength(7));
        ve = request.validate();
        assertThat(ve.isPresent(), is(false));
    }

    public void testRequestValidationFailureScenarios() throws IOException {
        {
            InvalidateApiKeyRequest request = new InvalidateApiKeyRequest("realm", "user", "api-kid", "api-kname");
            Optional<ValidationException> ve = request.validate();
            assertThat(ve.isPresent(), is(true));
            assertEquals(2, ve.get().validationErrors().size());
            assertThat(ve.get().validationErrors().get(0),
                    containsString("api key id must not be specified when username or realm name is specified"));
            assertThat(ve.get().validationErrors().get(1),
                    containsString("api key name must not be specified when username or realm name is specified"));
        }

        {
            InvalidateApiKeyRequest request = new InvalidateApiKeyRequest(null, null, "api-kid", "api-kname");
            Optional<ValidationException> ve = request.validate();
            assertThat(ve.isPresent(), is(true));
            assertEquals(1, ve.get().validationErrors().size());
            assertThat(ve.get().validationErrors().get(0),
                    containsString("api key name must not be specified when api key id is specified"));
        }

        {
            InvalidateApiKeyRequest request = new InvalidateApiKeyRequest("realm", null, null, "api-kname");
            Optional<ValidationException> ve = request.validate();
            assertThat(ve.isPresent(), is(true));
            assertEquals(1, ve.get().validationErrors().size());
            assertThat(ve.get().validationErrors().get(0),
                    containsString("api key name must not be specified when username or realm name is specified"));
        }
    }
}
