package com.pwn.probe;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Process;

public class BootReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context c, Intent i) {
        int uid = Process.myUid();
        Main.log("BootReceiver uid=" + uid + " action=" + i.getAction());
        if (uid == 0) {
            Main.writeOut("/sdcard/pwn_state.txt", "BootReceiver uid=0 -> console\n");
            Main.startConsole(c);
        } else {
            int r = Main.applyPatches();
            Main.log("boot applyPatches=" + r);
            Main.writeOut("/sdcard/pwn_state.txt", "BootReceiver uid=" + uid + " applyPatches=" + r + "\n");
            Main.scheduleRestart(c);
            Process.killProcess(Process.myPid());
        }
    }
}
