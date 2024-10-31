/*
 * Copyright (C) 2023-2024 The Evolution X Project
 * SPDX-License-Identifier: Apache-2.0
 */

package com.goolag.pif;

import android.os.Build;
import android.os.Bundle;

import androidx.preference.Preference;
import androidx.preference.PreferenceCategory;
import androidx.preference.PreferenceFragmentCompat;

import com.android.internal.util.custom.CustomUtils;
import com.android.internal.util.custom.certification.Android.PiHookProperties;
import com.android.settingslib.widget.TopIntroPreference;
import com.android.settings.custom.preference.SystemPropertySwitchPreference;

import java.util.ArrayList;

public class Pif extends PreferenceFragmentCompat implements Preference.OnPreferenceChangeListener {

    private TopIntroPreference mIntroPreference;
    private SystemPropertySwitchPreference mCertHook;
    private SystemPropertySwitchPreference mKeyBoxHook;

    @Override
    public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
        setPreferencesFromResource(R.xml.main, rootKey);

        mIntroPreference = findPreference("device_intro");
        mIntroPreference.setTitle(Build.MANUFACTURER + " " + Build.MODEL);

        mCertHook = (SystemPropertySwitchPreference) findPreference("persist.sys.certhook.enable");
        mCertHook.setOnPreferenceChangeListener(this);
        mKeyBoxHook = (SystemPropertySwitchPreference) findPreference("persist.sys.keyboxhook.enable");
        mKeyBoxHook.setOnPreferenceChangeListener(this);

        ArrayList<String> infoPrefs = new ArrayList<String>();
        infoPrefs.add("device");
        infoPrefs.add("fingerprint");
        infoPrefs.add("product");
        infoPrefs.add("model");
        infoPrefs.add("brand");
        infoPrefs.add("security_patch");
        infoPrefs.add("manufacturer");
        infoPrefs.add("board");
        infoPrefs.add("hardware");
        infoPrefs.add("device_initial_sdk_int");
        infoPrefs.add("release");
        infoPrefs.add("id");
        infoPrefs.add("incremental");
        infoPrefs.add("type");
        infoPrefs.add("tags");
        for (String i : infoPrefs) {
            setSummaryIfNotEmpty(i, false, "info");
        }
        // *_for_attestation
        infoPrefs.clear();
        infoPrefs.add("device");
        infoPrefs.add("product");
        infoPrefs.add("model");
        infoPrefs.add("brand");
        infoPrefs.add("manufacturer");
        for (String i : infoPrefs) {
            setSummaryIfNotEmpty(i, true, "attestation");
        }
    }

    @Override
    public boolean onPreferenceChange(Preference preference, Object newValue) {
        final String key = preference.getKey();
        switch (key) {
            case "persist.sys.certhook.enable":
            case "persist.sys.keyboxhook.enable":
                CustomUtils.restartApp("com.google.android.gms", getActivity());
                CustomUtils.restartApp("com.android.vending", getActivity());
                return true;
        }
        return false;
    }

    private boolean setSummaryIfNotEmpty(String prop, boolean attest, String category) {
        final Preference pref = findPreference(attest ? prop + "_for_attestation" : prop);
        String ret = PiHookProperties.get(prop, "", attest);
        if (ret.isEmpty()) {
            if (category != null) {
                PreferenceCategory categ = (PreferenceCategory) findPreference(category);
                categ.removePreference(pref);
            } else {
                getPreferenceScreen().removePreference(pref);
            }
            return false;
        }
        pref.setSummary(ret);
        return true;
    }
}
