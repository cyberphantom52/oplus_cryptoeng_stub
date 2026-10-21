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

import android.hardware.security.keymint.SecurityLevel;
import android.hardware.security.keymint.Tag;
import android.system.keystore2.Domain;
import android.system.keystore2.IKeystoreSecurityLevel;
import android.system.keystore2.KeyDescriptor;
import android.system.keystore2.KeyEntryResponse;

@VintfStability
interface IKeystoreService {

    IKeystoreSecurityLevel getSecurityLevel(in SecurityLevel securityLevel);

    KeyEntryResponse getKeyEntry(in KeyDescriptor key);

    void updateSubcomponent(in KeyDescriptor key, in @nullable byte[] publicCert,
                            in @nullable byte[] certificateChain);

    KeyDescriptor[] listEntries(in Domain domain, in long nspace);

    void deleteKey(in KeyDescriptor key);

    KeyDescriptor grant(in KeyDescriptor key, in int granteeUid, in int accessVector);

    void ungrant(in KeyDescriptor key, in int granteeUid);

    int getNumberOfEntries(in Domain domain, in long nspace);

    KeyDescriptor[] listEntriesBatched(in Domain domain, in long nspace,
            in @nullable String startingPastAlias);

    byte[] getSupplementaryAttestationInfo(in Tag tag);
}
