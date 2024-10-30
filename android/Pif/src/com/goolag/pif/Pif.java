/*
 * Copyright (C) 2023-2024 The Evolution X Project
 * SPDX-License-Identifier: Apache-2.0
 */

package com.goolag.pif;

import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;

import androidx.preference.Preference;
import androidx.preference.PreferenceCategory;
import androidx.preference.PreferenceFragmentCompat;
import androidx.preference.PreferenceManager;

import com.android.settingslib.widget.TopIntroPreference;

import com.goolag.pif.R;

import com.android.internal.util.custom.certification.Android;
import com.android.internal.util.custom.certification.Android.PiHookProperties;

public class Pif extends PreferenceFragmentCompat
        implements Preference.OnPreferenceChangeListener {

    private TopIntroPreference mIntroPreference;

    @Override
    public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
        setPreferencesFromResource(R.xml.main, rootKey);

        mIntroPreference = findPreference("device_intro");
        mIntroPreference.setTitle(Build.MANUFACTURER + " " + Build.MODEL);

        setSummaryIfNotEmpty("device", false);
        setSummaryIfNotEmpty("fingerprint", false);
        setSummaryIfNotEmpty("product", false);
        setSummaryIfNotEmpty("model", false);
        setSummaryIfNotEmpty("brand", false);
        setSummaryIfNotEmpty("security_patch", false);
        setSummaryIfNotEmpty("manufacturer", false);
        setSummaryIfNotEmpty("board", false);
        setSummaryIfNotEmpty("hardware", false);
        setSummaryIfNotEmpty("device_initial_sdk_int", false);
        setSummaryIfNotEmpty("release", false);
        setSummaryIfNotEmpty("id", false);
        setSummaryIfNotEmpty("incremental", false);
        setSummaryIfNotEmpty("type", false);
        setSummaryIfNotEmpty("tags", false);
        // *_for_attestation
        if (!setSummaryIfNotEmpty("device", true)
            && !setSummaryIfNotEmpty("product", true)
            && !setSummaryIfNotEmpty("model", true)
            && !setSummaryIfNotEmpty("brand", true)
            && !setSummaryIfNotEmpty("manufacturer", true)) {
            getPreferenceScreen().removePreference(findPreference("attestation"));
        }
    }

    @Override
    public boolean onPreferenceChange(Preference preference, Object newValue) {
        return true;
    }

    private boolean setSummaryIfNotEmpty(String prop, boolean attest) {
        final Preference pref = findPreference(attest ? prop + "_for_attestation" : prop);
        String ret = PiHookProperties.get(prop, "", attest);
        if (ret.isEmpty()) {
            getPreferenceScreen().removePreference(pref);
            return false;
        }
        pref.setSummary(ret);
        return true;
    }
}
