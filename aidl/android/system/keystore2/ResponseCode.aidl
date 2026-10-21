/*
 * Copyright 2020, The Android Open Source Project
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

package android.system.keystore2;

@VintfStability
@Backing(type="int")
enum ResponseCode {

    LOCKED = 2,
    UNINITIALIZED = 3,

    SYSTEM_ERROR = 4,

    PERMISSION_DENIED = 6,

    KEY_NOT_FOUND = 7,

    VALUE_CORRUPTED = 8,

    KEY_PERMANENTLY_INVALIDATED = 17,

    BACKEND_BUSY = 18,

    OPERATION_BUSY = 19,

    INVALID_ARGUMENT = 20,

    TOO_MUCH_DATA = 21,

    OUT_OF_KEYS = 22,

    OUT_OF_KEYS_REQUIRES_SYSTEM_UPGRADE = 23,

    OUT_OF_KEYS_PENDING_INTERNET_CONNECTIVITY = 24,

    OUT_OF_KEYS_TRANSIENT_ERROR = 25,

    OUT_OF_KEYS_PERMANENT_ERROR = 26,

    GET_ATTESTATION_APPLICATION_ID_FAILED = 27,

    INFO_NOT_AVAILABLE = 28,

    TOO_MANY_APP_KEYS = 29,

    TOO_MANY_APP_KEYS_SDK37 = 30,
}
