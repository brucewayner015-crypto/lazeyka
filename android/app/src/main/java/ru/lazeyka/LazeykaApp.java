package ru.lazeyka;

import android.app.Application;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;

import java.net.InetAddress;

public class LazeykaApp extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        Notifications.channels(this);
        // our app is outside the VPN, so the default network is the real one
        ConnectivityManager cm = getSystemService(ConnectivityManager.class);
        try {
            cm.registerDefaultNetworkCallback(new ConnectivityManager.NetworkCallback() {
                @Override
                public void onLinkPropertiesChanged(Network network, LinkProperties lp) {
                    StringBuilder sb = new StringBuilder();
                    for (InetAddress a : lp.getDnsServers()) {
                        if (sb.length() > 0) sb.append(',');
                        sb.append(a.getHostAddress());
                    }
                    Core.get(LazeykaApp.this).networkChanged(sb.toString());
                }
            });
        } catch (Exception ignored) {
        }
    }
}
