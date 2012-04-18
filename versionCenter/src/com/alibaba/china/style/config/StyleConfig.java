package com.alibaba.china.style.config;

public class StyleConfig {

    private String styleDocRoot;

    private String styleVsSourceFilePath;

    private int    coreProcess;

    private int    debugModel;

    private long   intervalSec;

    public String getStyleDocRoot() {
        return styleDocRoot;
    }

    public void setStyleDocRoot(String styleDocRoot) {
        this.styleDocRoot = styleDocRoot;
    }

    public String getStyleVsSourceFilePath() {
        return styleVsSourceFilePath;
    }

    public void setStyleVsSourceFilePath(String styleVsSourceFilePath) {
        this.styleVsSourceFilePath = styleVsSourceFilePath;
    }

    public int getCoreProcess() {
        return coreProcess;
    }

    public void setCoreProcess(int coreProcess) {
        this.coreProcess = coreProcess;
    }

    public int getDebugModel() {
        return debugModel;
    }

    public void setDebugModel(int debugModel) {
        this.debugModel = debugModel;
    }

    public long getIntervalSec() {
        return intervalSec;
    }

    public void setIntervalSec(long intervalSec) {
        this.intervalSec = intervalSec;
    }
}
