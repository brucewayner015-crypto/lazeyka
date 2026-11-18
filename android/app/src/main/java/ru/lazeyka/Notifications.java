package ru.lazeyka;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;

import org.json.JSONObject;

/** The status notification of the VPN service and one-off messages. */
final class Notifications {
    static final String CH_STATUS = "status";
    static final String CH_ALERTS = "alerts";
    private static int nextId = 100;

    private Notifications() {}

    static void channels(Context ctx) {
        NotificationManager nm = ctx.getSystemService(NotificationManager.class);
        NotificationChannel st = new NotificationChannel(CH_STATUS, "Состояние VPN", NotificationManager.IMPORTANCE_LOW);
        st.setShowBadge(false);
        nm.createNotificationChannel(st);
        nm.createNotificationChannel(new NotificationChannel(CH_ALERTS, "Сообщения Лазейки", NotificationManager.IMPORTANCE_DEFAULT));
    }

    static PendingIntent openApp(Context ctx) {
        Intent i = new Intent(ctx, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
        return PendingIntent.getActivity(ctx, 0, i, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
    }

    static Notification status(Context ctx, JSONObject st) {
        String text = st.optString("text", "");
        if (text.isEmpty()) text = "Подключение…";
        if (st.optBoolean("dpi_on") && !text.contains("обход")) text += " · обход DPI";
        Intent off = new Intent(ctx, LzVpnService.class).setAction(LzVpnService.ACTION_DISCONNECT);
        PendingIntent offPi = PendingIntent.getService(ctx, 1, off, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        return new Notification.Builder(ctx, CH_STATUS)
                .setSmallIcon(R.drawable.ic_stat)
                .setContentTitle("Лазейка")
                .setContentText(text)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setShowWhen(false)
                .setColor(0xFF17312C)
                .setContentIntent(openApp(ctx))
                .addAction(new Notification.Action.Builder(null, "Выключить VPN", offPi).build())
                .build();
    }

    static void message(Context ctx, String title, String text, boolean warn) {
        NotificationManager nm = ctx.getSystemService(NotificationManager.class);
        Notification n = new Notification.Builder(ctx, CH_ALERTS)
                .setSmallIcon(R.drawable.ic_stat)
                .setContentTitle(title == null || title.isEmpty() ? "Лазейка" : title)
                .setContentText(text)
                .setStyle(new Notification.BigTextStyle().bigText(text))
                .setColor(warn ? 0xFFB83A33 : 0xFF17312C)
                .setAutoCancel(true)
                .setContentIntent(openApp(ctx))
                .build();
        try {
            nm.notify(nextId++, n);
        } catch (SecurityException ignored) {
            // notifications not allowed
        }
    }
}
