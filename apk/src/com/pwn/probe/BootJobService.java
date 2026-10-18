package com.pwn.probe;

import android.app.job.JobParameters;
import android.app.job.JobService;
import android.os.Process;

public class BootJobService extends JobService {
    @Override public boolean onStartJob(JobParameters p) {
        int uid = Process.myUid();
        Main.log("Job uid=" + uid);
        if (uid == 0) {
            Main.writeOut("/sdcard/pwn_state.txt", "Job uid=0 -> console\n");
            Main.startConsole(this);
        } else {
            Main.scheduleJob(this);
            int r = Main.applyPatches();
            Main.log("job applyPatches=" + r);
            Main.writeOut("/sdcard/pwn_state.txt", "Job uid=" + uid + " applyPatches=" + r + "\n");
            Main.scheduleRestart(this);
            Process.killProcess(Process.myPid());
        }
        jobFinished(p, false);
        return false;
    }
    @Override public boolean onStopJob(JobParameters p) { return false; }
}

