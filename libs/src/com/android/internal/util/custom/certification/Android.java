package com.android.internal.util.custom.certification;

import android.app.Application;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.SystemProperties;
import android.security.keystore.KeyProperties;
import android.text.TextUtils;
import android.util.Log;

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
import com.android.internal.org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import com.android.internal.org.bouncycastle.openssl.PEMKeyPair;
import com.android.internal.org.bouncycastle.openssl.PEMParser;
import com.android.internal.org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import com.android.internal.org.bouncycastle.operator.ContentSigner;
import com.android.internal.org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import com.android.internal.org.bouncycastle.util.io.pem.PemReader;

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

public final class Android {

    private static final String TAG = Android.class.getSimpleName();
    private static final boolean DEBUG = false;

    private static Boolean sEnableCertHook =
            SystemProperties.getBoolean("persist.sys.certhook.enable", true);

    private static final PEMKeyPair EC, RSA;
    private static final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17");
    private static final List<Certificate> EC_CERTS = new ArrayList<>();
    private static final List<Certificate> RSA_CERTS = new ArrayList<>();
    private static final HashMap<String, Object> map;
    private static final CertificateFactory certificateFactory;

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
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");

            EC = parseKeyPair(Keybox.EC.PRIVATE_KEY);
            EC_CERTS.add(parseCert(Keybox.EC.CERTIFICATE_1));
            EC_CERTS.add(parseCert(Keybox.EC.CERTIFICATE_2));

            RSA = parseKeyPair(Keybox.RSA.PRIVATE_KEY);
            RSA_CERTS.add(parseCert(Keybox.RSA.CERTIFICATE_1));
            RSA_CERTS.add(parseCert(Keybox.RSA.CERTIFICATE_2));
        } catch (Throwable t) {
            Log.e(TAG, t.toString());
            throw new RuntimeException(t);
        }
    }

    public static boolean isCertHookEnabled() {
        return sEnableCertHook;
    }

    public static boolean isCertifiedPropsEmpty() {
        return map.isEmpty();
    }

    private static PEMKeyPair parseKeyPair(String key) throws Throwable {
        try (PEMParser parser = new PEMParser(new StringReader(key))) {
            return (PEMKeyPair) parser.readObject();
        }
    }

    private static Certificate parseCert(String cert) throws Throwable {
        try (PemReader reader = new PemReader(new StringReader(cert))) {
            return certificateFactory.generateCertificate(new ByteArrayInputStream(reader.readPemObject().getContent()));
        }
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
            return caList;
        }
        try {
            X509Certificate leaf = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(caList[0].getEncoded()));

            byte[] bytes = leaf.getExtensionValue(OID.getId());

            if (bytes == null) return caList;

            X509CertificateHolder holder = new X509CertificateHolder(leaf.getEncoded());

            Extension ext = holder.getExtension(OID);

            ASN1Sequence sequence = ASN1Sequence.getInstance(ext.getExtnValue().getOctets());

            ASN1Encodable[] encodables = sequence.toArray();

            ASN1Sequence teeEnforced = (ASN1Sequence) encodables[7];

            ASN1EncodableVector vector = new ASN1EncodableVector();

            for (ASN1Encodable asn1Encodable : teeEnforced) {
                ASN1TaggedObject taggedObject = (ASN1TaggedObject) asn1Encodable;
                if (taggedObject.getTagNo() == 704) continue;
                vector.add(taggedObject);
            }

            LinkedList<Certificate> certificates;

            X509v3CertificateBuilder builder;
            ContentSigner signer;

            if (KeyProperties.KEY_ALGORITHM_EC.equals(leaf.getPublicKey().getAlgorithm())) {
                certificates = new LinkedList<>(EC_CERTS);
                builder = new X509v3CertificateBuilder(new X509CertificateHolder(EC_CERTS.get(0).getEncoded()).getSubject(), holder.getSerialNumber(), holder.getNotBefore(), holder.getNotAfter(), holder.getSubject(), EC.getPublicKeyInfo());
                signer = new JcaContentSignerBuilder(leaf.getSigAlgName()).build(new JcaPEMKeyConverter().getPrivateKey(EC.getPrivateKeyInfo()));
            } else {
                certificates = new LinkedList<>(RSA_CERTS);
                builder = new X509v3CertificateBuilder(new X509CertificateHolder(RSA_CERTS.get(0).getEncoded()).getSubject(), holder.getSerialNumber(), holder.getNotBefore(), holder.getNotAfter(), holder.getSubject(), RSA.getPublicKeyInfo());
                signer = new JcaContentSignerBuilder(leaf.getSigAlgName()).build(new JcaPEMKeyConverter().getPrivateKey(RSA.getPrivateKeyInfo()));
            }

            byte[] verifiedBootKey = new byte[32];
            byte[] verifiedBootHash = new byte[32];

            ThreadLocalRandom.current().nextBytes(verifiedBootKey);
            ThreadLocalRandom.current().nextBytes(verifiedBootHash);

            ASN1Encodable[] rootOfTrustEnc = {new DEROctetString(verifiedBootKey), ASN1Boolean.TRUE, new ASN1Enumerated(0), new DEROctetString(verifiedBootHash)};

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

            certificates.addFirst(new JcaX509CertificateConverter().getCertificate(builder.build(signer)));

            return certificates.toArray(new Certificate[0]);

        } catch (Throwable t) {
            Log.e(TAG, t.toString());
        }
        return caList;
    }

    public static void dlog(String msg) {
        if (DEBUG) Log.d(TAG, msg);
    }
}
