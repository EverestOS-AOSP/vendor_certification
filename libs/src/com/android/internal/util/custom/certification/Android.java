package com.android.internal.util.custom.certification;

import android.app.Application;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.SystemProperties;
import android.security.keystore.KeyProperties;
import android.text.TextUtils;
import android.util.Log;
import android.system.keystore2.KeyEntryResponse;

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
import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import com.android.internal.org.bouncycastle.asn1.ASN1Boolean;
import com.android.internal.org.bouncycastle.asn1.ASN1Encodable;
import com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector;
import com.android.internal.org.bouncycastle.asn1.ASN1Enumerated;
import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.internal.org.bouncycastle.asn1.ASN1OctetString;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.ASN1TaggedObject;
import com.android.internal.org.bouncycastle.asn1.DEROctetString;
import com.android.internal.org.bouncycastle.asn1.DERSequence;
import com.android.internal.org.bouncycastle.asn1.DERTaggedObject;
import com.android.internal.org.bouncycastle.asn1.x509.Extension;
import com.android.internal.org.bouncycastle.cert.X509CertificateHolder;
import com.android.internal.org.bouncycastle.cert.X509v3CertificateBuilder;
import com.android.internal.org.bouncycastle.operator.ContentSigner;
import com.android.internal.org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * @hide
 */
public final class Android {

    private static final String TAG = Android.class.getSimpleName();
    private static final boolean DEBUG =
            SystemProperties.getBoolean("persist.sys.certhook.debug", false);;

    private static Boolean sEnableCertHook =
            SystemProperties.getBoolean("persist.sys.certhook.enable", true);
    private static Boolean sSupportsKeyBox =
            SystemProperties.getBoolean("persist.sys.certhook.supports.keybox", true);

    public class PiHookProperties {
        private static String getAttestProp(String property, boolean attest) {
            return TextUtils.formatSimple("persist.sys.pihooks.%s", attest ? property + "_for_attestation" : property);
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

    private static PrivateKey EC, RSA;
    private static byte[] EC_CERTS;
    private static byte[] RSA_CERTS;
    private static ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17");
    private static CertificateFactory certificateFactory;
    private static X509CertificateHolder EC_holder, RSA_holder;
    private static volatile String algo;

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
        String ret = PiHookProperties.get(prop, "", attest);
        if (ret.isEmpty()) return;
        switch(prop) {
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
            case "device_initial_sdk_int":
                if (!ret.equals("0")) {
                    map.put(prop.toUpperCase(), Integer.parseInt(ret));
                }
                break;
            default:
                map.put(prop.toUpperCase(), ret);
                break;
        }
    }

    private static void initCert() {
        if (!sSupportsKeyBox) return;

        try {
            certificateFactory = CertificateFactory.getInstance("X.509");

            EC = parsePrivateKey(Keybox.EC.PRIVATE_KEY, KeyProperties.KEY_ALGORITHM_EC);
            RSA = parsePrivateKey(Keybox.RSA.PRIVATE_KEY, KeyProperties.KEY_ALGORITHM_RSA);

            byte[] EC_cert1 = parseCert(Keybox.EC.CERTIFICATE_1);
            byte[] RSA_cert1 = parseCert(Keybox.RSA.CERTIFICATE_1);

            ByteArrayOutputStream stream = new ByteArrayOutputStream();

            stream.write(EC_cert1);
            stream.write(parseCert(Keybox.EC.CERTIFICATE_2));
            stream.write(parseCert(Keybox.EC.CERTIFICATE_3));

            EC_CERTS = stream.toByteArray();

            stream.reset();

            stream.write(RSA_cert1);
            stream.write(parseCert(Keybox.RSA.CERTIFICATE_2));
            stream.write(parseCert(Keybox.RSA.CERTIFICATE_3));

            RSA_CERTS = stream.toByteArray();

            stream.close();

            EC_holder = new X509CertificateHolder(EC_cert1);
            RSA_holder = new X509CertificateHolder(RSA_cert1);

        } catch (Throwable t) {
            dlog(Log.getStackTraceString(t));
            throw new RuntimeException(t);
        }
    }

    private static PrivateKey parsePrivateKey(String str, String algo) throws Throwable {
        byte[] bytes = Base64.getDecoder().decode(str);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
        return KeyFactory.getInstance(algo).generatePrivate(spec);
    }

    private static byte[] parseCert(String str) {
        return Base64.getDecoder().decode(str);
    }

    private static byte[] modifyLeaf(byte[] bytes) throws Throwable {
        X509Certificate leaf = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(bytes));

        if (leaf.getExtensionValue(OID.getId()) == null) throw new Exception();

        X509CertificateHolder holder = new X509CertificateHolder(leaf.getEncoded());

        Extension ext = holder.getExtension(OID);

        ASN1Sequence sequence = ASN1Sequence.getInstance(ext.getExtnValue().getOctets());

        ASN1Encodable[] encodables = sequence.toArray();

        ASN1Sequence teeEnforced = (ASN1Sequence) encodables[7];

        ASN1EncodableVector vector = new ASN1EncodableVector();

        ASN1Sequence rootOfTrust = null;
        for (ASN1Encodable asn1Encodable : teeEnforced) {
            ASN1TaggedObject taggedObject = (ASN1TaggedObject) asn1Encodable;
            if (taggedObject.getTagNo() == 704) {
                rootOfTrust = (ASN1Sequence) taggedObject.getObject();
                continue;
            }
            vector.add(asn1Encodable);
        }

        if (rootOfTrust == null) throw new Exception();

        algo = leaf.getPublicKey().getAlgorithm();

        boolean isEC = KeyProperties.KEY_ALGORITHM_EC.equals(algo);

        X509CertificateHolder cert1 = isEC ? EC_holder : RSA_holder;
        PrivateKey privateKey = isEC ? EC : RSA;

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(cert1.getSubject(),
            holder.getSerialNumber(), holder.getNotBefore(), holder.getNotAfter(),
            holder.getSubject(), holder.getSubjectPublicKeyInfo());
        ContentSigner signer = new JcaContentSignerBuilder(leaf.getSigAlgName()).build(privateKey);

        byte[] verifiedBootKey = new byte[32];
        ThreadLocalRandom.current().nextBytes(verifiedBootKey);

        DEROctetString verifiedBootHash = (DEROctetString) rootOfTrust.getObjectAt(3);

        if (verifiedBootHash == null) {
            byte[] temp = new byte[32];
            ThreadLocalRandom.current().nextBytes(temp);
            verifiedBootHash = new DEROctetString(temp);
        }

        ASN1Encodable[] rootOfTrustEnc = {new DEROctetString(verifiedBootKey),
            ASN1Boolean.TRUE, new ASN1Enumerated(0), new DEROctetString(verifiedBootHash)};

        ASN1Sequence rootOfTrustSeq = new DERSequence(rootOfTrustEnc);

        ASN1TaggedObject rootOfTrustTagObj = new DERTaggedObject(704, rootOfTrustSeq);

        vector.add(rootOfTrustTagObj);

        ASN1Sequence hackEnforced = new DERSequence(vector);

        encodables[7] = hackEnforced;

        ASN1Sequence hackedSeq = new DERSequence(encodables);

        ASN1OctetString hackedSeqOctets = new DEROctetString(hackedSeq);

        Extension hackedExt = new Extension(OID, false, hackedSeqOctets);

        builder.addExtension(hackedExt);

        for (ASN1ObjectIdentifier extensionOID : holder.getExtensions().getExtensionOIDs()) {
            if (OID.getId().equals(extensionOID.getId())) continue;
            builder.addExtension(holder.getExtension(extensionOID));
        }

        return builder.build(signer).getEncoded();
    }

    public static KeyEntryResponse onGetKeyEntry(KeyEntryResponse response) {
        if (!sSupportsKeyBox) {
            return response;
        }

        if (response == null)
            return null;

        if (response.metadata == null)
            return response;

        algo = null;

        try {
            byte[] newLeaf = modifyLeaf(response.metadata.certificate);
            response.metadata.certificateChain = getCertificateChain(algo);

            response.metadata.certificate = newLeaf;

        } catch (Throwable t) {
            dlog("onGetKeyEntry: " + t);
        }

        return response;
    }

    private static byte[] getCertificateChain(String algo) throws Throwable {
        if (KeyProperties.KEY_ALGORITHM_EC.equals(algo)) {
            return EC_CERTS;
        } else if (KeyProperties.KEY_ALGORITHM_RSA.equals(algo)) {
            return RSA_CERTS;
        }
        throw new Exception();
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

        if (caList == null || !sSupportsKeyBox) {
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
