package ru.lazeyka;

import android.Manifest;
import android.app.Activity;
import android.content.ContentValues;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Insets;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.MediaStore;
import android.text.Html;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.webkit.CookieManager;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.Toast;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/** The window: the core's web interface in a WebView, plus what only an Activity can do. */
public class MainActivity extends Activity implements Core.Listener {
    static final String ACTION_VPN_PERMISSION = "ru.lazeyka.VPN_PERMISSION";
    private static final int REQ_VPN = 1;
    private static final int REQ_FILE = 2;
    private static final int REQ_NOTIFY = 3;

    private WebView web;
    private String loadedUrl;
    private boolean askingVpn;
    private ValueCallback<Uri[]> fileCallback;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(Color.parseColor("#17312c"));
        web = new WebView(this);
        root.addView(web, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        // Android 15 draws apps edge to edge: keep the page clear of the bars
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            if (Build.VERSION.SDK_INT >= 30) {
                Insets i = insets.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.ime());
                v.setPadding(i.left, i.top, i.right, i.bottom);
            } else {
                v.setPadding(insets.getSystemWindowInsetLeft(), insets.getSystemWindowInsetTop(),
                        insets.getSystemWindowInsetRight(), insets.getSystemWindowInsetBottom());
            }
            return insets;
        });
        setContentView(root);
        setupWebView();
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, REQ_NOTIFY);
        }
        Core core = Core.get(this);
        core.addListener(this);
        core.start(false);
        handleIntent(getIntent());
        onCoreChanged();
    }

    @Override
    protected void onDestroy() {
        Core.get(this).removeListener(this);
        web.destroy();
        super.onDestroy();
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIntent(intent);
    }

    @Override
    protected void onResume() {
        super.onResume();
        Core core = Core.get(this);
        if (!core.running() && core.url() == null && core.error() == null) core.start(false);
        if (core.waitingForPermission()) askVpn();
    }

    @Override
    @SuppressWarnings("deprecation")
    public void onBackPressed() {
        // keep the page (and its state) alive: the app stays in recents
        moveTaskToBack(true);
    }

    @SuppressWarnings("SetJavaScriptEnabled")
    private void setupWebView() {
        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setCacheMode(WebSettings.LOAD_NO_CACHE);
        s.setAllowFileAccess(false);
        s.setAllowContentAccess(false);
        s.setSupportZoom(false);
        s.setTextZoom(100);
        CookieManager.getInstance().setAcceptCookie(true);
        web.setBackgroundColor(Color.parseColor("#e7edef"));
        web.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest req) {
                Uri u = req.getUrl();
                if ("lazeyka".equals(u.getScheme())) {
                    if ("restart".equals(u.getHost())) {
                        loadedUrl = null;
                        Core.get(MainActivity.this).start(false);
                        onCoreChanged();
                    }
                    return true;
                }
                if ("127.0.0.1".equals(u.getHost())) return false;
                // help pages, GitHub and the like open in the browser
                try {
                    startActivity(new Intent(Intent.ACTION_VIEW, u));
                } catch (Exception ignored) {
                }
                return true;
            }
        });
        web.setWebChromeClient(new WebChromeClient() {
            @Override
            public boolean onShowFileChooser(WebView view, ValueCallback<Uri[]> cb, FileChooserParams params) {
                if (fileCallback != null) fileCallback.onReceiveValue(null);
                fileCallback = cb;
                Intent i = new Intent(Intent.ACTION_GET_CONTENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*");
                try {
                    startActivityForResult(Intent.createChooser(i, "Файл конфигурации"), REQ_FILE);
                } catch (Exception e) {
                    fileCallback = null;
                    return false;
                }
                return true;
            }
        });
        web.setDownloadListener((url, ua, disposition, mime, length) -> download(url));
    }

    // --- core ----------------------------------------------------------------

    @Override
    public void onCoreChanged() {
        Core core = Core.get(this);
        String url = core.url();
        if (url != null) {
            if (!url.equals(loadedUrl)) {
                loadedUrl = url;
                web.loadUrl(url);
            }
            return;
        }
        loadedUrl = null;
        String err = core.error();
        if (err != null) {
            page("Лазейка остановилась", Html.escapeHtml(err), "<a href='lazeyka://restart'>Запустить снова</a>");
        } else {
            page("Лазейка", "Запускается…", "");
        }
    }

    private void page(String title, String text, String action) {
        String html = "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
                + "<body style='margin:0;font:16px/1.5 sans-serif;background:#17312c;color:#e4ece9;display:flex;"
                + "align-items:center;justify-content:center;min-height:100vh;text-align:center'><div style='padding:24px'>"
                + "<h1 style='font-weight:600;font-size:28px;margin:0 0 8px'>" + title + "</h1>"
                + "<p style='color:#b9c9c4'>" + text + "</p>"
                + "<p><style>a{color:#d98b1c;font-size:18px}</style>" + action + "</p></div>";
        web.loadDataWithBaseURL("about:blank", html, "text/html", "utf-8", null);
    }

    // --- intents ---------------------------------------------------------------

    private void handleIntent(Intent intent) {
        if (intent == null) return;
        String action = intent.getAction();
        if (ACTION_VPN_PERMISSION.equals(action)) {
            askVpn();
            return;
        }
        String text = null;
        if (Intent.ACTION_VIEW.equals(action) && intent.getData() != null) {
            Uri u = intent.getData();
            String scheme = u.getScheme();
            if ("content".equals(scheme) || "file".equals(scheme)) text = readUri(u);
            else text = u.toString();
        } else if (Intent.ACTION_SEND.equals(action)) {
            text = intent.getStringExtra(Intent.EXTRA_TEXT);
            Uri stream = intent.getParcelableExtra(Intent.EXTRA_STREAM);
            if (text == null && stream != null) text = readUri(stream);
        }
        if (text != null && !text.trim().isEmpty()) {
            try {
                JSONObject d = new JSONObject();
                d.put("text", text);
                Core.get(this).sendEvent("import", d);
                Toast.makeText(this, "Добавляю в Лазейку…", Toast.LENGTH_SHORT).show();
            } catch (Exception ignored) {
            }
        }
        // handled once: a rotation must not import again
        intent.setAction(Intent.ACTION_MAIN);
        intent.setData(null);
    }

    private String readUri(Uri u) {
        try (InputStream in = getContentResolver().openInputStream(u)) {
            if (in == null) return null;
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0 && out.size() < (4 << 20)) out.write(buf, 0, n);
            return out.toString(StandardCharsets.UTF_8.name());
        } catch (Exception e) {
            Toast.makeText(this, "Не удалось прочитать файл: " + e.getMessage(), Toast.LENGTH_LONG).show();
            return null;
        }
    }

    private void askVpn() {
        if (askingVpn) return;
        Intent i = VpnService.prepare(this);
        if (i == null) {
            Core.get(this).permissionResult(true);
            return;
        }
        askingVpn = true;
        try {
            startActivityForResult(i, REQ_VPN);
        } catch (Exception e) {
            askingVpn = false;
            Core.get(this).permissionResult(false);
        }
    }

    @Override
    protected void onActivityResult(int req, int result, Intent data) {
        super.onActivityResult(req, result, data);
        if (req == REQ_VPN) {
            askingVpn = false;
            Core.get(this).permissionResult(result == RESULT_OK);
            if (result != RESULT_OK) {
                Toast.makeText(this, "Без разрешения VPN Лазейка не сможет работать", Toast.LENGTH_LONG).show();
            }
        } else if (req == REQ_FILE && fileCallback != null) {
            Uri u = (result == RESULT_OK && data != null) ? data.getData() : null;
            fileCallback.onReceiveValue(u == null ? null : new Uri[]{u});
            fileCallback = null;
        }
    }

    // --- downloads (the diagnostics report) ------------------------------------

    private void download(String url) {
        final String cookie = CookieManager.getInstance().getCookie(url);
        new Thread(() -> {
            String msg;
            try {
                HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
                if (cookie != null) c.setRequestProperty("Cookie", cookie);
                byte[] body;
                try (InputStream in = c.getInputStream()) {
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    byte[] buf = new byte[8192];
                    int n;
                    while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
                    body = out.toByteArray();
                }
                String name = "lazeyka-diag-" + System.currentTimeMillis() / 1000 + ".txt";
                msg = "Сохранено в «Загрузки»: " + name;
                if (Build.VERSION.SDK_INT >= 29) {
                    ContentValues v = new ContentValues();
                    v.put(MediaStore.Downloads.DISPLAY_NAME, name);
                    v.put(MediaStore.Downloads.MIME_TYPE, "text/plain");
                    Uri dst = getContentResolver().insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, v);
                    if (dst == null) throw new Exception("нет доступа к «Загрузкам»");
                    try (OutputStream o = getContentResolver().openOutputStream(dst)) {
                        if (o == null) throw new Exception("нет доступа к «Загрузкам»");
                        o.write(body);
                    }
                } else {
                    File dir = getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS);
                    File f = new File(dir, name);
                    try (FileOutputStream o = new FileOutputStream(f)) {
                        o.write(body);
                    }
                    msg = "Сохранено: " + f.getAbsolutePath();
                }
            } catch (Exception e) {
                msg = "Не удалось сохранить: " + e.getMessage();
            }
            final String m = msg;
            runOnUiThread(() -> Toast.makeText(this, m, Toast.LENGTH_LONG).show());
        }, "lz-download").start();
    }

    @Override
    public void onRequestPermissionsResult(int req, String[] perms, int[] results) {
        super.onRequestPermissionsResult(req, perms, results);
    }

    @SuppressWarnings("unused")
    private static void hide(View v) {
        v.setVisibility(View.GONE);
    }
}
