package com.android.internal.util.custom.certification;

import android.app.Application;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.SystemProperties;
import android.security.keystore.KeyProperties;
import android.text.TextUtils;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.lang.reflect.Field;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

/**
 * @hide
 */
public final class Android {

    private static final String TAG = Android.class.getSimpleName();
    private static final boolean DEBUG = false;

    private static Boolean sEnableCertHook =
            SystemProperties.getBoolean("persist.sys.certhook.enable", true);

    private static final HashMap<String, Object> map;

    private static final String cert_device = SystemProperties.get("persist.sys.pihooks.device", "");
    private static final String cert_fp = SystemProperties.get("persist.sys.pihooks.fingerprint", "");
    private static final String cert_model = SystemProperties.get("persist.sys.pihooks.model", "");
    private static final String cert_spl = SystemProperties.get("persist.sys.pihooks.security_patch", "");
    private static final String cert_manufacturer = SystemProperties.get("persist.sys.pihooks.manufacturer", "");
    private static final String cert_board = SystemProperties.get("persist.sys.pihooks.board", "");
    private static final String cert_hardware = SystemProperties.get("persist.sys.pihooks.hardware", "");
    private static final int cert_sdk = SystemProperties.getInt("persist.sys.pihooks.api_level", 0);

    static {
        Map<String, Object> tMap = new HashMap<>();
        String[] sections = cert_fp.split("/");
        if (!cert_manufacturer.isEmpty()) tMap.put("MANUFACTURER", cert_manufacturer);
        if (!cert_model.isEmpty()) tMap.put("MODEL", cert_model);
        if (!cert_fp.isEmpty()) {
            tMap.put("FINGERPRINT", cert_fp);
            tMap.put("BRAND", sections[0]);
            tMap.put("PRODUCT", sections[1]);
            tMap.put("RELEASE", sections[2].split(":")[1]);
            tMap.put("ID", sections[3]);
            tMap.put("INCREMENTAL", sections[4].split(":")[0]);
            tMap.put("TYPE", sections[4].split(":")[1]);
            tMap.put("TAGS", sections[5]);
        }
        if (!cert_device.isEmpty()) tMap.put("DEVICE", cert_device);
        if (!cert_spl.isEmpty()) tMap.put("SECURITY_PATCH", cert_spl);
        if (!cert_board.isEmpty()) tMap.put("BOARD", cert_board);
        if (!cert_hardware.isEmpty()) tMap.put("HARDWARE", cert_hardware);
        if (cert_sdk != 0) tMap.put("DEVICE_INITIAL_SDK_INT", cert_sdk);
        map = new HashMap<>(tMap);
    }

    public static boolean isCertHookEnabled() {
        return sEnableCertHook;
    }

    public static boolean isCertifiedPropsEmpty() {
        return map.isEmpty();
    }

    private static Field getField(String fieldName) {
        Field field = null;
        try {
            field = Build.class.getDeclaredField(fieldName);
        } catch (Throwable ignored) {
            try {
                field = Build.VERSION.class.getDeclaredField(fieldName);
            } catch (Throwable t) {
                Log.e(TAG, "Couldn't find field " + fieldName);
            }
        }
        return field;
    }

    public static boolean hasSystemFeature(boolean ret, String name) {
        if (PackageManager.FEATURE_KEYSTORE_APP_ATTEST_KEY.equals(name)
            || PackageManager.FEATURE_STRONGBOX_KEYSTORE.equals(name)) {
            return false;
        }
        return ret;
    }

    public static void newApplication() {
        if (!sEnableCertHook) return;

        map.forEach((k, v) -> setPropValue(k, v)); 
    }

    private static void setPropValue(String key, Object value) {
        try {
            if (value == null || (value instanceof String && ((String) value).isEmpty())) {
                dlog("setPropValue: Skipping setting empty value for key: " + key);
                return;
            }
            dlog("setPropValue: Setting property for key: " + key + ", value: " + value.toString());
            Field field;
            Class<?> targetClass;
            try {
                targetClass = Build.class;
                field = targetClass.getDeclaredField(key);
            } catch (NoSuchFieldException e) {
                targetClass = Build.VERSION.class;
                field = targetClass.getDeclaredField(key);
            }
            if (field != null) {
                field.setAccessible(true);
                Class<?> fieldType = field.getType();
                if (fieldType == int.class || fieldType == Integer.class) {
                    if (value instanceof Integer) {
                        field.set(null, value);
                    } else if (value instanceof String) {
                        int convertedValue = Integer.parseInt((String) value);
                        field.set(null, convertedValue);
                        dlog("setPropValue: Converted value for key " + key + ": " + convertedValue);
                    }
                } else if (fieldType == String.class) {
                    field.set(null, String.valueOf(value));
                }
                field.setAccessible(false);
            }
        } catch (IllegalAccessException | NoSuchFieldException e) {
            dlog("setPropValue: Failed to set prop " + key);
        } catch (NumberFormatException e) {
            dlog("setPropValue: Failed to parse value for field " + key);
        }
    }

    private static boolean isCallerSafetyNet() {
        if (!sEnableCertHook) return false;

        return Arrays.stream(Thread.currentThread().getStackTrace())
                        .anyMatch(elem -> elem.getClassName().toLowerCase(java.util.Locale.US)
                            .contains("droidguard"));
    }

    public static Certificate[] engineGetCertificateChain(Certificate[] caList) {
        if (!sEnableCertHook) return caList;

        if (caList == null
            || !SystemProperties.getBoolean("persist.sys.pihooks.supports.keybox", false)) {
            if (isCallerSafetyNet()) {
                throw new UnsupportedOperationException();
            }
        }

        return caList;
    }

    public static void dlog(String msg) {
        if (DEBUG) Log.d(TAG, msg);
    }
}
