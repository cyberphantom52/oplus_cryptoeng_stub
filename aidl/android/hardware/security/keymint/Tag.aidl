/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.hardware.security.keymint;

import android.hardware.security.keymint.TagType;

@VintfStability
@Backing(type="int")
enum Tag {

    INVALID = 0,

    PURPOSE = TagType.ENUM_REP | 1,

    ALGORITHM = TagType.ENUM | 2,

    KEY_SIZE = TagType.UINT | 3,

    BLOCK_MODE = TagType.ENUM_REP | 4,

    DIGEST = TagType.ENUM_REP | 5,

    PADDING = TagType.ENUM_REP | 6,

    CALLER_NONCE = TagType.BOOL | 7,

    MIN_MAC_LENGTH = TagType.UINT | 8,

    EC_CURVE = TagType.ENUM | 10,

    ML_DSA_VARIANT = TagType.ENUM | 11,

    RSA_PUBLIC_EXPONENT = TagType.ULONG | 200,

    INCLUDE_UNIQUE_ID = TagType.BOOL | 202,

    RSA_OAEP_MGF_DIGEST = TagType.ENUM_REP | 203,

    BOOTLOADER_ONLY = TagType.BOOL | 302,

    ROLLBACK_RESISTANCE = TagType.BOOL | 303,

    HARDWARE_TYPE = TagType.ENUM | 304,

    EARLY_BOOT_ONLY = TagType.BOOL | 305,

    ACTIVE_DATETIME = TagType.DATE | 400,

    ORIGINATION_EXPIRE_DATETIME = TagType.DATE | 401,

    USAGE_EXPIRE_DATETIME = TagType.DATE | 402,

    MIN_SECONDS_BETWEEN_OPS = TagType.UINT | 403,

    MAX_USES_PER_BOOT = TagType.UINT | 404,

    USAGE_COUNT_LIMIT = TagType.UINT | 405,

    USER_ID = TagType.UINT | 501,

    USER_SECURE_ID = TagType.ULONG_REP | 502,

    NO_AUTH_REQUIRED = TagType.BOOL | 503,

    USER_AUTH_TYPE = TagType.ENUM | 504,

    AUTH_TIMEOUT = TagType.UINT | 505,

    ALLOW_WHILE_ON_BODY = TagType.BOOL | 506,

    TRUSTED_USER_PRESENCE_REQUIRED = TagType.BOOL | 507,

    TRUSTED_CONFIRMATION_REQUIRED = TagType.BOOL | 508,

    UNLOCKED_DEVICE_REQUIRED = TagType.BOOL | 509,

    APPLICATION_ID = TagType.BYTES | 601,

    APPLICATION_DATA = TagType.BYTES | 700,

    CREATION_DATETIME = TagType.DATE | 701,

    ORIGIN = TagType.ENUM | 702,

    ROOT_OF_TRUST = TagType.BYTES | 704,

    OS_VERSION = TagType.UINT | 705,

    OS_PATCHLEVEL = TagType.UINT | 706,

    UNIQUE_ID = TagType.BYTES | 707,

    ATTESTATION_CHALLENGE = TagType.BYTES | 708,

    ATTESTATION_APPLICATION_ID = TagType.BYTES | 709,

    ATTESTATION_ID_BRAND = TagType.BYTES | 710,

    ATTESTATION_ID_DEVICE = TagType.BYTES | 711,

    ATTESTATION_ID_PRODUCT = TagType.BYTES | 712,

    ATTESTATION_ID_SERIAL = TagType.BYTES | 713,

    ATTESTATION_ID_IMEI = TagType.BYTES | 714,

    ATTESTATION_ID_MEID = TagType.BYTES | 715,

    ATTESTATION_ID_MANUFACTURER = TagType.BYTES | 716,

    ATTESTATION_ID_MODEL = TagType.BYTES | 717,

    VENDOR_PATCHLEVEL = TagType.UINT | 718,

    BOOT_PATCHLEVEL = TagType.UINT | 719,

    DEVICE_UNIQUE_ATTESTATION = TagType.BOOL | 720,

    IDENTITY_CREDENTIAL_KEY = TagType.BOOL | 721,

    STORAGE_KEY = TagType.BOOL | 722,

    ATTESTATION_ID_SECOND_IMEI = TagType.BYTES | 723,

    MODULE_HASH = TagType.BYTES | 724,

    ASSOCIATED_DATA = TagType.BYTES | 1000,

    NONCE = TagType.BYTES | 1001,

    MAC_LENGTH = TagType.UINT | 1003,

    RESET_SINCE_ID_ROTATION = TagType.BOOL | 1004,

    CONFIRMATION_TOKEN = TagType.BYTES | 1005,

    CERTIFICATE_SERIAL = TagType.BIGNUM | 1006,

    CERTIFICATE_SUBJECT = TagType.BYTES | 1007,

    CERTIFICATE_NOT_BEFORE = TagType.DATE | 1008,

    CERTIFICATE_NOT_AFTER = TagType.DATE | 1009,

    MAX_BOOT_LEVEL = TagType.UINT | 1010,
}
