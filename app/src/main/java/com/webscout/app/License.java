package com.webscout.app;

import android.content.Context;
import android.provider.Settings;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

/**
 * Activation keys have the form  WS1.<payload>.<signature>
 * payload (base64url JSON): {"d": device id, "e": expiry unix seconds or 0, "f": ["deep", ...]}
 * signature: RSA-SHA256 over the payload text, made by the developer's private key (never in the app).
 */
final class License {

    // Public key only (DER, base64). Create the key pair with termux/make_dev_key.sh and paste it here.
    static final String PUBLIC_KEY_B64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwEWbt+eiIAmDSXerTLDDKVF+bBX85nwelB3FeBQtglHNhN4sjx9xF4SDjzpxLF3jYdaEeLmGFX9JPWf2gG+vWNOrRwe5HlZDk234uMGJ/k7RZUVXDfjxHCia5OmAEfhpNIeNo0H0q5fyG68XaWDMNiGmD4eGnyvLA+uA04t2gkQT0trCm9FgExiWmcBqaRG0ihv3PVxqMM4weGHs/skU6ZC/FRSY4JKwmKvjD5bQXMIBpY7R/LHe7+lOxXHczAHPNpb9V3wRqopIHsacUXx0tulPCHRRc9FWD7GxIkzDOeV5LUvEbbkJiMFvsDpTX/AmXUqMzjcG1Og4ijgS9TqcJQIDAQAB";

    private static final String PREF = "license";

    private License() {}

    static String deviceId(Context c) {
        String id = Settings.Secure.getString(c.getContentResolver(), Settings.Secure.ANDROID_ID);
        return id == null ? "" : id.toLowerCase();
    }

    /** Returns "ok", or a reason: invalid, device, expired. */
    static String verify(Context c, String key) {
        try {
            String[] parts = key.trim().split("\\.");
            if (parts.length != 3 || !"WS1".equals(parts[0])) return "invalid";

            PublicKey pk = KeyFactory.getInstance("RSA").generatePublic(
                    new X509EncodedKeySpec(Base64.decode(PUBLIC_KEY_B64, Base64.DEFAULT)));
            Signature v = Signature.getInstance("SHA256withRSA");
            v.initVerify(pk);
            v.update(parts[1].getBytes(StandardCharsets.US_ASCII));
            if (!v.verify(decode(parts[2]))) return "invalid";

            JSONObject p = new JSONObject(new String(decode(parts[1]), StandardCharsets.UTF_8));
            if (!deviceId(c).equals(p.optString("d", "").toLowerCase())) return "device";
            long exp = p.optLong("e", 0);
            if (exp != 0 && System.currentTimeMillis() / 1000L > exp) return "expired";
            return "ok";
        } catch (Exception e) {
            return "invalid";
        }
    }

    static boolean isActive(Context c) {
        String k = stored(c);
        return k != null && "ok".equals(verify(c, k));
    }

    static String key(Context c) {
        String k = stored(c);
        return k == null ? "" : k;
    }

    static String featuresJson(Context c) {
        String k = stored(c);
        if (k == null || !"ok".equals(verify(c, k))) return "[]";
        try {
            String[] parts = k.trim().split("\\.");
            JSONArray f = new JSONObject(new String(decode(parts[1]), StandardCharsets.UTF_8)).optJSONArray("f");
            return f == null ? "[]" : f.toString();
        } catch (Exception e) {
            return "[]";
        }
    }

    static void save(Context c, String key) {
        c.getSharedPreferences(PREF, Context.MODE_PRIVATE).edit().putString("key", key.trim()).apply();
    }

    private static String stored(Context c) {
        return c.getSharedPreferences(PREF, Context.MODE_PRIVATE).getString("key", null);
    }

    /** base64url without padding (the server writes it that way). */
    private static byte[] decode(String s) {
        String p = s;
        while (p.length() % 4 != 0) p += "=";
        return Base64.decode(p, Base64.URL_SAFE);
    }
}
