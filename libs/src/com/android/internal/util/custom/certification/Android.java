package com.android.internal.util.custom.certification;

import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Environment;
import android.os.SystemProperties;
import android.text.TextUtils;
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * @hide
 */
public final class Android {

    private static final String TAG = Android.class.getSimpleName();
    private static final boolean DEBUG =
            SystemProperties.getBoolean("persist.sys.certhook.debug", false);
    private static final String DATA_FILE = "gms_certified_props.json";

    private static Boolean sEnableCertHook =
            SystemProperties.getBoolean("persist.sys.certhook.enable", true);

    public class PiHookProperties {
        private static String getAttestProp(String property, boolean attest) {
            return TextUtils.formatSimple(
                    "persist.sys.pihooks.%s", attest ? property + "_for_attestation" : property);
        }

        public static String get(String property, String defVal, boolean attest) {
            return SystemProperties.get(getAttestProp(property, attest), defVal);
        }

        public static int getInt(String property, int defVal, boolean attest) {
            return SystemProperties.getInt(getAttestProp(property, attest), defVal);
        }

        public static boolean getBoolean(String property, boolean defVal, boolean attest) {
            return SystemProperties.getBoolean(getAttestProp(property, attest), defVal);
        }
    }

    private static final HashMap<String, Object> map = new HashMap<>();

    static {
        putIfNotEmpty("device", map, false);
        putIfNotEmpty("fingerprint", map, false);
        putIfNotEmpty("product", map, false);
        putIfNotEmpty("model", map, false);
        putIfNotEmpty("brand", map, false);
        putIfNotEmpty("security_patch", map, false);
        putIfNotEmpty("manufacturer", map, false);
        putIfNotEmpty("board", map, false);
        putIfNotEmpty("hardware", map, false);
        putIfNotEmpty("device_initial_sdk_int", map, false);
        putIfNotEmpty("release", map, false);
        putIfNotEmpty("id", map, false);
        putIfNotEmpty("incremental", map, false);
        putIfNotEmpty("type", map, false);
        putIfNotEmpty("tags", map, false);
        // *_for_attestation
        putIfNotEmpty("device", map, true);
        putIfNotEmpty("product", map, true);
        putIfNotEmpty("model", map, true);
        putIfNotEmpty("brand", map, true);
        putIfNotEmpty("manufacturer", map, true);
    }

    private static void putIfNotEmpty(String prop, Map<String, Object> map, boolean attest) {
        if (prop.equals("device_initial_sdk_int")) {
            int ret = PiHookProperties.getInt(prop, 0, attest);
            if (ret > 0) {
                map.put(prop.toUpperCase(), ret);
            }
            return;
        }

        String ret = PiHookProperties.get(prop, "", attest);
        if (ret.isEmpty()) return;
        switch (prop) {
            case "fingerprint":
                String[] sections = ret.split("/");
                map.put(prop.toUpperCase(), ret);
                map.put("PRODUCT", sections[1]);
                map.put("BRAND", sections[0]);
                map.put("RELEASE", sections[2].split(":")[1]);
                map.put("ID", sections[3]);
                map.put("INCREMENTAL", sections[4].split(":")[0]);
                map.put("TYPE", sections[4].split(":")[1]);
                map.put("TAGS", sections[5]);
                break;
            default:
                map.put(prop.toUpperCase(), ret);
                break;
        }
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
                dlog("Couldn't find field " + fieldName);
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

        // Load dynamic props from gms_certified_props.json
        File dataFile = new File(Environment.getDataSystemDirectory(), DATA_FILE);
        String savedProps = readFromFile(dataFile);

        if (!TextUtils.isEmpty(savedProps)) {
            try {
                dlog("Parsing props fetched by attestation service");
                JSONObject parsedProps = new JSONObject(savedProps);
                Iterator<String> keys = parsedProps.keys();

                while (keys.hasNext()) {
                    String key = keys.next();
                    String value = parsedProps.getString(key);
                    setPropValue(key, value);
                }
                return;
            } catch (JSONException e) {
                dlog("Error parsing JSON data: " + e.getMessage());
                // Fall back to default props
                map.forEach((k, v) -> setPropValue(k, v));
            }
        } else {
            dlog("Using default device props - data file unavailable");
            map.forEach((k, v) -> setPropValue(k, v));
        }
    }

    private static String readFromFile(File file) {
        StringBuilder content = new StringBuilder();

        if (file.exists()) {
            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    content.append(line);
                }
            } catch (IOException e) {
                dlog("Error reading from file: " + e.getMessage());
            }
        }
        return content.toString();
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
                } else if (fieldType == long.class || fieldType == Long.class) {
                    if (value instanceof Long) {
                        field.set(null, value);
                    } else if (value instanceof String) {
                        long convertedValue = Long.parseLong((String) value);
                        field.set(null, convertedValue);
                        dlog("setPropValue: Converted value for key " + key + ": " + convertedValue);
                    }
                } else if (fieldType == boolean.class || fieldType == Boolean.class) {
                    if (value instanceof Boolean) {
                        field.set(null, value);
                    } else if (value instanceof String) {
                        boolean convertedValue = Boolean.parseBoolean((String) value);
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
                .anyMatch(
                        elem ->
                                elem.getClassName()
                                        .toLowerCase(java.util.Locale.US)
                                        .contains("droidguard"));
    }

    public static Certificate[] engineGetCertificateChain(Certificate[] caList) {
        if (!sEnableCertHook) return caList;

        if (caList == null) {
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
