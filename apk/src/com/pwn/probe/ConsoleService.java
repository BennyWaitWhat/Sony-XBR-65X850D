package com.pwn.probe;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

public class ConsoleService extends Service {
    private Thread t;
    @Override public void onCreate() {
        super.onCreate();
        try {
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            NotificationChannel ch = new NotificationChannel("pwn", "root console", NotificationManager.IMPORTANCE_MIN);
            nm.createNotificationChannel(ch);
            Notification n = new Notification.Builder(this, "pwn")
                    .setContentTitle("root console")
                    .setContentText("listening on 4445")
                    .setSmallIcon(android.R.drawable.ic_menu_manage)
                    .build();
            startForeground(1, n);
        } catch (Throwable t) { android.util.Log.e("PWNROOT", "fg err " + t); }
    }
    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (t == null || !t.isAlive()) { t = new Thread(new Console()); t.start(); }
        return START_STICKY;
    }
    @Override public IBinder onBind(Intent i) { return null; }
}
