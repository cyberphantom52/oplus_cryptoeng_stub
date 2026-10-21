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

@VintfStability
@Backing(type="int")
enum TagType {

    INVALID = 0 << 28,

    ENUM = 1 << 28,

    ENUM_REP = 2 << 28,

    UINT = 3 << 28,

    UINT_REP = 4 << 28,

    ULONG = 5 << 28,

    DATE = 6 << 28,

    BOOL = 7 << 28,

    BIGNUM = 8 << 28,

    BYTES = 9 << 28,

    ULONG_REP = 10 << 28,
}
