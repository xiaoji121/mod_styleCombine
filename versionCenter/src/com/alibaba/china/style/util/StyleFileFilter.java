package com.alibaba.china.style.util;

import java.io.File;

public class StyleFileFilter {

    private String[] patterns;

    private StyleFileFilter(String... patterns){
        if (patterns == null) {
            throw new NullPointerException();
        }
        this.patterns = patterns;
    }

    public boolean accept(File pathname) {
        if (pathname.isDirectory()) {
            return true;
        }
        for (int i = 0; i < patterns.length; i++) {
            if (pathname.getName().endsWith(patterns[i])) {
                return true;
            }
        }
        return false;
    }
}
