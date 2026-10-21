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

package android.system.keystore2;

import android.hardware.security.keymint.KeyParameter;
import android.system.keystore2.AuthenticatorSpec;
import android.system.keystore2.CreateOperationResponse;
import android.system.keystore2.EphemeralStorageKeyResponse;
import android.system.keystore2.IKeystoreOperation;
import android.system.keystore2.KeyDescriptor;
import android.system.keystore2.KeyMetadata;

@VintfStability
@SensitiveData
interface IKeystoreSecurityLevel {

    const int KEY_FLAG_AUTH_BOUND_WITHOUT_CRYPTOGRAPHIC_LSKF_BINDING = 0x1;

    CreateOperationResponse createOperation(in KeyDescriptor key,
                  in KeyParameter[] operationParameters, in boolean forced);

    KeyMetadata generateKey(in KeyDescriptor key, in @nullable KeyDescriptor attestationKey,
                            in KeyParameter[] params, in int flags, in byte[] entropy);

    KeyMetadata importKey(in KeyDescriptor key, in @nullable KeyDescriptor attestationKey,
                          in KeyParameter[] params, in int flags, in byte[] keyData);

    KeyMetadata importWrappedKey(in KeyDescriptor key, in KeyDescriptor wrappingKey,
                                 in @nullable byte[] maskingKey, in KeyParameter[] params,
                                 in AuthenticatorSpec[] authenticators);

    EphemeralStorageKeyResponse convertStorageKeyToEphemeral(in KeyDescriptor storageKey);

    void deleteKey(in KeyDescriptor key);
}
