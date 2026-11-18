package ru.lazeyka;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;

/** Quick settings tile: VPN on/off without opening the app. */
public class ToggleTile extends TileService {

    static void refresh(Context ctx) {
        try {
            TileService.requestListeningState(ctx, new ComponentName(ctx, ToggleTile.class));
        } catch (Exception ignored) {
        }
    }

    @Override
    public void onStartListening() {
        update();
    }

    private void update() {
        Tile t = getQsTile();
        if (t == null) return;
        boolean on = Core.get(this).vpnOn();
        t.setState(on ? Tile.STATE_ACTIVE : Tile.STATE_INACTIVE);
        t.setLabel("Лазейка");
        t.updateTile();
    }

    @Override
    @SuppressWarnings("deprecation")
    public void onClick() {
        Core core = Core.get(this);
        if (VpnService.prepare(this) != null) {
            // the permission dialog needs the app
            Intent i = new Intent(this, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            if (android.os.Build.VERSION.SDK_INT >= 34) {
                startActivityAndCollapse(android.app.PendingIntent.getActivity(this, 2, i,
                        android.app.PendingIntent.FLAG_IMMUTABLE | android.app.PendingIntent.FLAG_UPDATE_CURRENT));
            } else {
                startActivityAndCollapse(i);
            }
            return;
        }
        if (!core.running()) {
            core.start(false);
            core.sendEvent("connect", null);
        } else {
            core.sendEvent("toggle_vpn", null);
        }
        Tile t = getQsTile();
        if (t != null) {
            t.setState(core.vpnOn() ? Tile.STATE_INACTIVE : Tile.STATE_ACTIVE);
            t.updateTile();
        }
    }
}
