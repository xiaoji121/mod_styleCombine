package com.alibaba.china.style.interval;

import java.util.Date;
import java.util.Timer;
import java.util.TimerTask;

import com.alibaba.china.style.StyleVersionProcessor;

public class TimerStart {

    private StyleVersionProcessor proc;

    public TimerStart(StyleVersionProcessor proc){
        this.proc = proc;
    }

    public void startTimer() {
        Timer timer = new Timer("styleVersion", false);
        TimerTask task = new TimerTask() {

            public void run() {
                start(proc);
            }
        };
        timer.scheduleAtFixedRate(task, getMills(1), getMills(proc.getpConfig().getIntervalSec()));
    }

    private synchronized void start(StyleVersionProcessor svp) {
        System.out.println("start:\t" + new Date().toLocaleString());
        long start = System.currentTimeMillis();
        boolean resultFlag = false;
        try {
            resultFlag = svp.execute();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        long end = System.currentTimeMillis();
        System.out.println("execute status is : " + resultFlag);
        System.out.println("total const time: " + ((end - start)) + " ms");
        System.out.println("end :\t" + new Date().toLocaleString());
    }

    private static long getMills(long sec) {
        return sec * 1000; // get millseconde
    }
}
