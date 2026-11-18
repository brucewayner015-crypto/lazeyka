package ru.lazeyka;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageInfo;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.net.Network;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.provider.Settings;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileDescriptor;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Runs Лазейка's core (the same Go program as on Windows, built for Linux)
 * as a child process and serves its requests: the VPN interface, the
 * notification, the list of installed apps. See internal/host in the core.
 */
public final class Core {
    static final String TAG = "Lazeyka";

    public interface Listener {
        void onCoreChanged();
    }

    private static Core instance;

    public static synchronized Core get(Context ctx) {
        if (instance == null) instance = new Core(ctx.getApplicationContext());
        return instance;
    }

    private final Context ctx;
    private final Handler main = new Handler(Looper.getMainLooper());
    private final List<Listener> listeners = new CopyOnWriteArrayList<>();
    private final List<JSONObject> pendingEvents = new ArrayList<>();
    private final Object writeLock = new Object();

    private Process process;
    private LocalServerSocket server;
    private LocalSocket conn;
    private volatile String url;
    private volatile String error;
    private volatile boolean quitting;
    private volatile JSONObject status = new JSONObject();

    // the VPN permission dialog, shown by MainActivity
    private CountDownLatch permissionLatch;
    private volatile boolean permissionOk;

    private Core(Context ctx) {
        this.ctx = ctx;
    }

    public String url() { return url; }
    public String error() { return error; }
    public JSONObject status() { return status; }
    public boolean running() { return process != null; }
    public boolean vpnOn() { return status.optBoolean("vpn_on", false); }

    public void addListener(Listener l) { listeners.add(l); }
    public void removeListener(Listener l) { listeners.remove(l); }

    private void changed() {
        main.post(() -> {
            for (Listener l : listeners) l.onCoreChanged();
        });
    }

    /** Starts the core if it is not running. */
    public synchronized void start(boolean autostart) {
        if (process != null) return;
        quitting = false;
        error = null;
        url = null;
        String lib = ctx.getApplicationInfo().nativeLibraryDir;
        File exe = new File(lib, "liblazeyka.so");
        if (!exe.exists()) {
            error = "В приложении нет ядра Лазейки (" + exe + ")";
            changed();
            return;
        }
        try {
            byte[] rnd = new byte[8];
            new SecureRandom().nextBytes(rnd);
            StringBuilder name = new StringBuilder("lazeyka-");
            for (byte b : rnd) name.append(String.format(Locale.ROOT, "%02x", b));
            server = new LocalServerSocket(name.toString());
            File home = new File(ctx.getFilesDir(), "lazeyka");
            //noinspection ResultOfMethodCallIgnored
            home.mkdirs();
            ProcessBuilder pb = new ProcessBuilder(exe.getAbsolutePath());
            pb.directory(home);
            pb.redirectErrorStream(true);
            Map<String, String> env = pb.environment();
            env.put("LAZEYKA_HOST_SOCKET", "@" + name);
            env.put("LAZEYKA_HOME", home.getAbsolutePath());
            env.put("LAZEYKA_MIHOMO", new File(lib, "libmihomo.so").getAbsolutePath());
            env.put("LAZEYKA_BYEDPI", new File(lib, "libbyedpi.so").getAbsolutePath());
            env.put("LAZEYKA_OSVER", Build.VERSION.RELEASE);
            env.put("LAZEYKA_MODEL", Build.MANUFACTURER + " " + Build.MODEL);
            String id = Settings.Secure.getString(ctx.getContentResolver(), Settings.Secure.ANDROID_ID);
            env.put("LAZEYKA_DEVICE_ID", id == null ? "" : id);
            env.put("LAZEYKA_DNS", dnsServers());
            env.put("LAZEYKA_AUTOSTART", autostart ? "1" : "0");
            env.put("SSL_CERT_DIR", "/system/etc/security/cacerts");
            env.put("TZ", TimeZone.getDefault().getID());
            env.put("HOME", home.getAbsolutePath());
            env.put("TMPDIR", ctx.getCacheDir().getAbsolutePath());
            process = pb.start();
        } catch (Exception e) {
            Log.e(TAG, "start core", e);
            error = "Не удалось запустить ядро: " + e.getMessage();
            closeServer();
            process = null;
            changed();
            return;
        }
        final Process p = process;
        new Thread(() -> pumpOutput(p), "lz-core-out").start();
        new Thread(this::acceptLoop, "lz-core-sock").start();
        new Thread(() -> waitExit(p), "lz-core-wait").start();
        changed();
    }

    /** Asks the core to quit (it switches the VPN off first). */
    public void quit() {
        quitting = true;
        sendEvent("quit", null);
    }

    private void pumpOutput(Process p) {
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) Log.i(TAG, line);
        } catch (Exception ignored) {
        }
    }

    private void waitExit(Process p) {
        int code = -1;
        try {
            code = p.waitFor();
        } catch (InterruptedException ignored) {
        }
        Log.w(TAG, "core exited: " + code);
        synchronized (this) {
            if (process == p) process = null;
            url = null;
            if (!quitting && error == null) error = "Ядро Лазейки остановилось (код " + code + ")";
            closeServer();
            try {
                if (conn != null) conn.close();
            } catch (Exception ignored) {
            }
            conn = null;
        }
        status = new JSONObject();
        LzVpnService.stopFromCore(ctx);
        changed();
    }

    private synchronized void closeServer() {
        try {
            if (server != null) server.close();
        } catch (Exception ignored) {
        }
        server = null;
    }

    private void acceptLoop() {
        LocalServerSocket srv;
        synchronized (this) {
            srv = server;
        }
        if (srv == null) return;
        LocalSocket s;
        try {
            s = srv.accept();
        } catch (Exception e) {
            Log.w(TAG, "accept: " + e);
            return;
        }
        try {
            if (s.getPeerCredentials().getUid() != android.os.Process.myUid()) {
                Log.e(TAG, "foreign connection to the core socket");
                s.close();
                return;
            }
        } catch (Exception e) {
            return;
        }
        synchronized (this) {
            conn = s;
        }
        closeServer(); // one core, one connection
        List<JSONObject> queued;
        synchronized (pendingEvents) {
            queued = new ArrayList<>(pendingEvents);
            pendingEvents.clear();
        }
        for (JSONObject ev : queued) write(ev, null);
        try (BufferedReader r = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                final JSONObject m;
                try {
                    m = new JSONObject(line);
                } catch (Exception e) {
                    continue;
                }
                handle(m);
            }
        } catch (Exception e) {
            Log.w(TAG, "core socket: " + e);
        }
    }

    private void handle(JSONObject m) {
        String op = m.optString("op");
        long id = m.optLong("id", 0);
        JSONObject args = m.optJSONObject("args");
        switch (op) {
            case "ready":
                url = args != null ? args.optString("url") : null;
                error = null;
                changed();
                break;
            case "fatal":
                error = args != null ? args.optString("error") : "ошибка ядра";
                changed();
                break;
            case "status":
                if (args == null) break;
                if (args.optBoolean("notify")) {
                    Notifications.message(ctx, args.optString("title"), args.optString("text"), args.optBoolean("warn"));
                } else {
                    status = args;
                    LzVpnService.statusChanged(ctx);
                    ToggleTile.refresh(ctx);
                    changed();
                }
                break;
            case "show":
                Intent i = new Intent(ctx, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                try {
                    ctx.startActivity(i);
                } catch (Exception ignored) {
                }
                break;
            case "tun_open":
                // may wait for the user's permission: off the reader thread
                new Thread(() -> openTun(id, args), "lz-tun").start();
                break;
            case "tun_close":
                LzVpnService.closeTun(ctx);
                reply(id, true, null, null, null);
                break;
            case "apps":
                new Thread(() -> listApps(id), "lz-apps").start();
                break;
            default:
                if (id != 0) reply(id, false, "неизвестная операция " + op, null, null);
        }
    }

    private void openTun(long id, JSONObject args) {
        if (VpnService.prepare(ctx) != null) {
            if (!askPermission()) {
                reply(id, false, "Лазейке не разрешено создавать VPN: откройте приложение и разрешите", null, null);
                return;
            }
        }
        try {
            ParcelFileDescriptor pfd = LzVpnService.openTun(ctx, args == null ? new JSONObject() : args);
            reply(id, true, null, null, pfd.getFileDescriptor());
        } catch (Exception e) {
            Log.e(TAG, "tun", e);
            reply(id, false, e.getMessage() == null ? e.toString() : e.getMessage(), null, null);
        }
    }

    /** Shows the system VPN dialog through MainActivity and waits for the answer. */
    private boolean askPermission() {
        CountDownLatch latch = new CountDownLatch(1);
        synchronized (this) {
            permissionLatch = latch;
            permissionOk = false;
        }
        Intent i = new Intent(ctx, MainActivity.class)
                .setAction(MainActivity.ACTION_VPN_PERMISSION)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        try {
            ctx.startActivity(i);
        } catch (Exception e) {
            Notifications.message(ctx, "Лазейка", "Откройте Лазейку, чтобы разрешить VPN", true);
        }
        try {
            latch.await(110, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
        }
        return permissionOk && VpnService.prepare(ctx) == null;
    }

    /** MainActivity reports the dialog's result. */
    public void permissionResult(boolean ok) {
        CountDownLatch l;
        synchronized (this) {
            permissionOk = ok;
            l = permissionLatch;
            permissionLatch = null;
        }
        if (l != null) l.countDown();
    }

    public synchronized boolean waitingForPermission() {
        return permissionLatch != null;
    }

    private void listApps(long id) {
        try {
            PackageManager pm = ctx.getPackageManager();
            JSONArray out = new JSONArray();
            for (PackageInfo pi : pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)) {
                if (pi.applicationInfo == null || pi.packageName.equals(ctx.getPackageName())) continue;
                boolean net = false;
                if (pi.requestedPermissions != null) {
                    for (String p : pi.requestedPermissions) {
                        if ("android.permission.INTERNET".equals(p)) {
                            net = true;
                            break;
                        }
                    }
                }
                if (!net) continue;
                JSONObject a = new JSONObject();
                a.put("package", pi.packageName);
                a.put("label", String.valueOf(pi.applicationInfo.loadLabel(pm)));
                a.put("system", (pi.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0
                        && (pi.applicationInfo.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0);
                out.put(a);
            }
            reply(id, true, null, out, null);
        } catch (Exception e) {
            reply(id, false, e.toString(), null, null);
        }
    }

    private void reply(long id, boolean ok, String err, Object data, FileDescriptor fd) {
        try {
            JSONObject r = new JSONObject();
            r.put("id", id);
            r.put("ok", ok);
            if (err != null) r.put("error", err);
            if (data != null) r.put("data", data);
            write(r, fd);
        } catch (Exception e) {
            Log.w(TAG, "reply: " + e);
        }
    }

    /** Sends an event; before the core connects, events wait in a queue. */
    public void sendEvent(String name, JSONObject data) {
        try {
            JSONObject ev = new JSONObject();
            ev.put("event", name);
            if (data != null) ev.put("data", data);
            synchronized (this) {
                if (conn == null) {
                    synchronized (pendingEvents) {
                        pendingEvents.add(ev);
                    }
                    return;
                }
            }
            write(ev, null);
        } catch (Exception e) {
            Log.w(TAG, "event: " + e);
        }
    }

    private void write(JSONObject o, FileDescriptor fd) {
        LocalSocket s;
        synchronized (this) {
            s = conn;
        }
        if (s == null) return;
        byte[] b = (o.toString() + "\n").getBytes(StandardCharsets.UTF_8);
        synchronized (writeLock) {
            try {
                OutputStream out = s.getOutputStream();
                if (fd != null) s.setFileDescriptorsForSend(new FileDescriptor[]{fd});
                out.write(b);
                out.flush();
                if (fd != null) s.setFileDescriptorsForSend(null);
            } catch (Exception e) {
                Log.w(TAG, "write: " + e);
            }
        }
    }

    /** The current network's DNS servers ("1.2.3.4,5.6.7.8"). */
    String dnsServers() {
        StringBuilder sb = new StringBuilder();
        try {
            ConnectivityManager cm = ctx.getSystemService(ConnectivityManager.class);
            Network n = cm.getActiveNetwork();
            LinkProperties lp = n == null ? null : cm.getLinkProperties(n);
            if (lp != null) {
                for (InetAddress a : lp.getDnsServers()) {
                    if (sb.length() > 0) sb.append(',');
                    sb.append(a.getHostAddress());
                }
            }
        } catch (Exception ignored) {
        }
        return sb.toString();
    }

    /** The network changed: the core's own resolver follows it. */
    void networkChanged(String dns) {
        if (dns == null || dns.isEmpty() || !running()) return;
        try {
            JSONObject d = new JSONObject();
            JSONArray arr = new JSONArray();
            for (String s : dns.split(",")) arr.put(s);
            d.put("dns", arr);
            sendEvent("network", d);
        } catch (Exception ignored) {
        }
    }
}
