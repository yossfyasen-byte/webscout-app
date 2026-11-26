package com.zerospecter.app;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.os.Build;
import android.os.Bundle;
import android.webkit.JavascriptInterface;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;

/**
 * يفتح واجهة ZeroSpecter اللي بتشتغل بتيرمكس على 127.0.0.1:8765.
 * إذا السيرفر مش شغّال بتظهر صفحة بزر "تشغيل السيرفر" بيشغّله عبر Termux.
 */
public class MainActivity extends Activity {

    private static final String SERVER = "http://127.0.0.1:8765/";
    private static final String OFFLINE = "file:///android_asset/offline.html";
    private static final String RUN_PERMISSION = "com.termux.permission.RUN_COMMAND";
    private static final int REQ_RUN = 7;

    private WebView web;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setStatusBarColor(Color.parseColor("#0B0D12"));
        getWindow().setNavigationBarColor(Color.parseColor("#151922"));

        web = new WebView(this);
        web.setBackgroundColor(Color.parseColor("#0B0D12"));
        setContentView(web);

        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setAllowFileAccess(false);          // ملفات assets تبقى شغّالة
        s.setAllowContentAccess(false);

        web.addJavascriptInterface(new Bridge(), "Android");
        web.setWebViewClient(new WebViewClient() {
            @Override
            public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                if (request.isForMainFrame()) {
                    view.loadUrl(OFFLINE);
                }
            }
        });

        web.loadUrl(SERVER);
    }

    private boolean termuxInstalled() {
        try {
            getPackageManager().getPackageInfo("com.termux", 0);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
    }

    private void launchTermuxServer() {
        if (!termuxInstalled()) {
            Toast.makeText(this, "تيرمكس غير مثبّت", Toast.LENGTH_LONG).show();
            return;
        }
        if (checkSelfPermission(RUN_PERMISSION) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{RUN_PERMISSION}, REQ_RUN);
            return;
        }
        try {
            Intent i = new Intent();
            i.setClassName("com.termux", "com.termux.app.RunCommandService");
            i.setAction("com.termux.RUN_COMMAND");
            i.putExtra("com.termux.RUN_COMMAND_PATH", "/data/data/com.termux/files/usr/bin/bash");
            i.putExtra("com.termux.RUN_COMMAND_ARGUMENTS",
                    new String[]{"-lc", "cd ~/zerospecter-ui && exec python zs_server.py"});
            i.putExtra("com.termux.RUN_COMMAND_WORKDIR", "/data/data/com.termux/files/home");
            i.putExtra("com.termux.RUN_COMMAND_BACKGROUND", true);
            if (Build.VERSION.SDK_INT >= 26) {
                startForegroundService(i);
            } else {
                startService(i);
            }
            Toast.makeText(this, "عم أشغّل السيرفر...", Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            Toast.makeText(this,
                    "ما زبط التشغيل. تأكد من allow-external-apps بتيرمكس (شوف README)",
                    Toast.LENGTH_LONG).show();
        }
    }

    @Override
    public void onRequestPermissionsResult(int code, String[] perms, int[] results) {
        super.onRequestPermissionsResult(code, perms, results);
        if (code == REQ_RUN && results.length > 0 && results[0] == PackageManager.PERMISSION_GRANTED) {
            launchTermuxServer();
        } else if (code == REQ_RUN) {
            Toast.makeText(this, "لازم تسمح للتطبيق بتشغيل أوامر تيرمكس", Toast.LENGTH_LONG).show();
        }
    }

    @Override
    public void onBackPressed() {
        if (web != null && web.canGoBack()) {
            web.goBack();
        } else {
            super.onBackPressed();
        }
    }

    /** جسر بسيط: تشغيل السيرفر من صفحة offline، وإشعار من الواجهة. */
    private class Bridge {
        @JavascriptInterface
        public void startServer() {
            runOnUiThread(MainActivity.this::launchTermuxServer);
        }

        @JavascriptInterface
        public void toast(String msg) {
            runOnUiThread(() -> Toast.makeText(MainActivity.this, msg, Toast.LENGTH_SHORT).show());
        }
    }
}
