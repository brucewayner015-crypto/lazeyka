package ru.lazeyka;

import android.app.Notification;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Owns the VPN interface. The core asks for it (tun_open), this service
 * builds it and hands the descriptor back; mihomo reads and writes packets.
 * Our own app is always excluded, so the core, mihomo and ByeDPI reach the
 * network directly instead of looping into the tunnel.
 */
public class LzVpnService extends VpnService {
    static final String ACTION_OPEN = "ru.lazeyka.OPEN";
    static final String ACTION_STOP = "ru.lazeyka.STOP";
    static final String ACTION_DISCONNECT = "ru.lazeyka.DISCONNECT";
    static final int NOTIFICATION_ID = 1;

    private static volatile LzVpnService running;
    private static CountDownLatch startedLatch;

    private ParcelFileDescriptor tun;

    // --- called by Core ------------------------------------------------------

    /** Starts the service (if needed) and builds a new interface. */
    static ParcelFileDescriptor openTun(Context ctx, JSONObject p) throws Exception {
        LzVpnService s = ensureRunning(ctx);
        if (s == null) throw new Exception("служба VPN не запустилась");
        return s.establish(p);
    }

    static void closeTun(Context ctx) {
        LzVpnService s = running;
        if (s != null) s.shutdown();
    }

    static void stopFromCore(Context ctx) {
        closeTun(ctx);
    }

    static void statusChanged(Context ctx) {
        LzVpnService s = running;
        if (s != null) s.showNotification();
    }

    private static LzVpnService ensureRunning(Context ctx) throws InterruptedException {
        if (running != null) return running;
        CountDownLatch l;
        synchronized (LzVpnService.class) {
            if (startedLatch == null) startedLatch = new CountDownLatch(1);
            l = startedLatch;
        }
        Intent i = new Intent(ctx, LzVpnService.class).setAction(ACTION_OPEN);
        ctx.startForegroundService(i);
        l.await(15, TimeUnit.SECONDS);
        return running;
    }

    // --- service -------------------------------------------------------------

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();
        showNotification(); // must happen quickly after startForegroundService
        if (ACTION_STOP.equals(action)) {
            shutdown();
            return START_NOT_STICKY;
        }
        if (ACTION_DISCONNECT.equals(action)) {
            Core.get(this).sendEvent("disconnect", null);
            if (!Core.get(this).running()) shutdown();
            return START_NOT_STICKY;
        }
        running = this;
        synchronized (LzVpnService.class) {
            if (startedLatch != null) startedLatch.countDown();
            startedLatch = null;
        }
        if (!ACTION_OPEN.equals(action)) {
            // started by Android: "Always-on VPN" or after the app was killed
            Core core = Core.get(this);
            core.start(true);
            core.sendEvent("connect", null);
        }
        return START_STICKY;
    }

    private synchronized ParcelFileDescriptor establish(JSONObject p) throws Exception {
        Builder b = new Builder();
        b.setSession(p.optString("session", "Лазейка"));
        b.setMtu(p.optInt("mtu", 1500));
        String[] a4 = p.optString("address4", "198.18.0.1/30").split("/");
        b.addAddress(a4[0], Integer.parseInt(a4[1]));
        b.addRoute("0.0.0.0", 0);
        String a6 = p.optString("address6", "");
        if (!a6.isEmpty()) {
            // IPv6 goes into the tunnel too (and dies there): otherwise it
            // would leave past the VPN
            String[] x = a6.split("/");
            b.addAddress(x[0], Integer.parseInt(x[1]));
            b.addRoute("::", 0);
        }
        b.addDnsServer(p.optString("dns", "198.18.0.2"));
        b.addDisallowedApplication(getPackageName());
        JSONArray bypass = p.optJSONArray("bypass_apps");
        if (bypass != null) {
            for (int i = 0; i < bypass.length(); i++) {
                try {
                    b.addDisallowedApplication(bypass.getString(i));
                } catch (PackageManager.NameNotFoundException ignored) {
                    // not installed
                }
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) b.setMetered(false);
        b.setUnderlyingNetworks(null);
        b.setConfigureIntent(Notifications.openApp(this));
        ParcelFileDescriptor fd = b.establish();
        if (fd == null) throw new Exception("Android не дал создать VPN (нет разрешения)");
        ParcelFileDescriptor old = tun;
        tun = fd;
        if (old != null) {
            try {
                old.close();
            } catch (Exception ignored) {
            }
        }
        showNotification();
        return fd;
    }

    private synchronized void shutdown() {
        if (tun != null) {
            try {
                tun.close();
            } catch (Exception ignored) {
            }
            tun = null;
        }
        running = null;
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    void showNotification() {
        Notification n = Notifications.status(this, Core.get(this).status());
        try {
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
            } else {
                startForeground(NOTIFICATION_ID, n);
            }
        } catch (Exception e) {
            Log.w(Core.TAG, "foreground: " + e);
        }
    }

    @Override
    public void onRevoke() {
        // another VPN took over, or the user switched us off in Android
        Core.get(this).sendEvent("revoked", null);
        shutdown();
    }

    @Override
    public void onDestroy() {
        if (running == this) running = null;
        super.onDestroy();
    }
}
