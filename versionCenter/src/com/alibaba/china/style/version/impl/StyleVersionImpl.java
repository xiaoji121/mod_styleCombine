package com.alibaba.china.style.version.impl;

import java.io.File;
import java.io.FileFilter;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Formatter;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import com.alibaba.china.style.config.StyleConfig;
import com.alibaba.china.style.file.FileDesc;
import com.alibaba.china.style.util.IOUtil;
import com.alibaba.china.style.version.StyleVersion;

public class StyleVersionImpl implements StyleVersion {

    private static FileFilter styleFilter = new MyFileFilter(FILE_TYPE_CSS, FILE_TYPE_JS);

    @Override
    public Map<String, FileDesc> getStyleVersion(String filePath) {
        StringBuilder path = new StringBuilder();
        if (null != filePath) {
            path.append(filePath);
        }
        path.append(File.separator).append(STYLE_VERSION_FILE_NAME).append(BYTE_STYLE_VERSION_EXT);

        File file = new File(path.toString());
        Map<String, FileDesc> resultMap = IOUtil.getVersionObject(file);
        if (null == resultMap) {
            file = new File(path.append("_old").toString());
            resultMap = IOUtil.getVersionObject(file);
            if (null == resultMap) {
                return new HashMap<String, FileDesc>(0);
            }
        }
        return resultMap;
    }

    @Override
    public boolean builderStyleVersion(File filePath, List<FileDesc> fileDescList) {
        if (fileDescList == null || null == filePath) {
            return false;
        }
        return IOUtil.writeString(filePath, getStyleVersionString(fileDescList));
    }

    @Override
    public boolean diffAndCombine(List<FileDesc> fileDescList, Map<String, FileDesc> sourceFd, StyleConfig pConfig) {

        String styleDocRoot = pConfig.getStyleDocRoot();

        long start = 0, end = 0;
        if (1 == pConfig.getDebugModel()) {
            start = System.currentTimeMillis();
        }
        List<File> fileList = new LinkedList<File>();
        IOUtil.getFilesList(new File(styleDocRoot), fileList, styleFilter);

        if (1 == pConfig.getDebugModel()) {
            end = System.currentTimeMillis();
            System.out.println("find files const time: " + ((end - start)) + " ms");
        }

        if ('/' == styleDocRoot.charAt(styleDocRoot.length() - 1)) {
            styleDocRoot = styleDocRoot.substring(0, styleDocRoot.length() - 1);
        }

        // debug
        if (1 == pConfig.getDebugModel()) {
            start = System.currentTimeMillis();
        }

        boolean flag = false;

        int size = fileList.size();
        if (size < 1000 || pConfig.getCoreProcess() <= 0) {
            pConfig.setCoreProcess(1);
        }
        int coreCounts = pConfig.getCoreProcess();
        int part = (int) Math.ceil((double) size / coreCounts);

        List<FileMerge> callList = new ArrayList<FileMerge>(coreCounts);
        ExecutorService exec = Executors.newFixedThreadPool(coreCounts);

        for (int i = 0; i < coreCounts; i++) {
            int sIndex = i * part;
            int eIndex = sIndex + part;

            // debug
            if (1 == pConfig.getDebugModel()) {
                System.out.println("subList: " + sIndex + "===" + eIndex);
            }
            final List<File> subList = fileList.subList(sIndex, Math.min(eIndex, size));

            FileMerge fm = new FileMerge(subList, sourceFd, fileDescList, styleDocRoot);
            callList.add(fm);
        }

        List<Future<Boolean>> futureList = null;
        try {
            futureList = exec.invokeAll(callList);
            for (Future<Boolean> ft : futureList) {
                boolean r = ft.get();
                if (r && !flag) {
                    flag = true;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        exec.shutdown();
        // debug
        if (1 == pConfig.getDebugModel()) {
            end = System.currentTimeMillis();
            System.out.println("merge const time: " + ((end - start)) + " ms");
        }
        return flag;
    }

    private static class FileMerge implements Callable<Boolean> {

        private List<File>            fileList;
        private Map<String, FileDesc> sourceFd;
        private List<FileDesc>        fileDescList;
        private String                styleDocRoot;

        public FileMerge(List<File> fileList, Map<String, FileDesc> sourceFd, List<FileDesc> fileDescList,
                         String styleDocRoot){
            super();
            this.fileList = fileList;
            this.sourceFd = sourceFd;
            this.fileDescList = fileDescList;
            this.styleDocRoot = styleDocRoot;
        }

        private boolean merge() {
            boolean hasUpdate = false;
            for (File file : fileList) {
                String relativePath = getRelativePath(styleDocRoot, file.getAbsolutePath());
                FileDesc srcFd = sourceFd.get(relativePath);

                if (null != srcFd && srcFd.getLastModified() == file.lastModified()) {
                    fileDescList.add(srcFd);
                    continue;
                }

                byte[] input = IOUtil.bytesRead(file.getAbsolutePath());
                String md5Sum = md5sum(input);

                long newVersion = Math.abs(md5Sum.hashCode());
                /*
                 * if new version equals old version, need to fix the version
                 */
                if (null != srcFd && newVersion == srcFd.getVersion()) {
                    ++newVersion;
                }

                FileDesc newFd = new FileDesc();
                newFd.setPath(relativePath);
                newFd.setType(getFileType(file.getName()));
                newFd.setLastModified(file.lastModified());
                newFd.setMd5Sum(md5Sum);
                newFd.setSize(file.length());
                newFd.setVersion(newVersion);

                if (null != srcFd && newFd.equals(srcFd)) {
                    // set new lastModified time
                    srcFd.setLastModified(file.lastModified());
                    fileDescList.add(srcFd);
                    continue;
                }
                fileDescList.add(newFd);
                if (!hasUpdate) {
                    hasUpdate = true;
                }
            }
            return hasUpdate;
        }

        @Override
        public Boolean call() throws Exception {
            return merge();
        }

    }

    private static String getRelativePath(String rootPath, String abstPath) {
        if (abstPath == null || rootPath == null) {
            return abstPath;
        }
        if (rootPath.length() >= abstPath.length()) {
            return abstPath;
        }

        String r = abstPath.substring(0, rootPath.length());
        if (rootPath.equals(r)) {
            return abstPath.substring(rootPath.length());
        }
        return abstPath;
    }

    private static String md5sum(byte[] input) {
        StringBuilder buf = new StringBuilder();
        if (null == input) {
            return buf.toString();
        }
        byte[] rby = null;
        try {
            MessageDigest md5msg = MessageDigest.getInstance("MD5");
            rby = md5msg.digest(input);
        } catch (Exception e) {
            e.printStackTrace();
        }
        for (int i = 0; i < rby.length; i++) {
            String s = new Formatter().format("%02x", rby[i]).toString();
            buf.append(s);
        }
        return buf.toString();
    }

    private static String getStyleVersionString(List<FileDesc> fileDescList) {

        StringBuilder buf = new StringBuilder();
        if (null == fileDescList) {
            return buf.toString();
        }

        for (FileDesc fd : fileDescList) {
            buf.append(fd.getPath()).append("=").append(fd.getVersion());
            buf.append("\n");
        }
        return buf.toString();
    }

    private static String getFileType(String str) {
        if (null == str) {
            return null;
        }
        if (str.endsWith(FILE_TYPE_CSS)) {
            return FILE_TYPE_CSS;
        } else if (str.endsWith(FILE_TYPE_JS)) {
            return FILE_TYPE_JS;
        }
        return null;
    }

    private static class MyFileFilter implements FileFilter {

        private String[] patterns;

        private MyFileFilter(String... patterns){
            if (patterns == null) {
                throw new NullPointerException();
            }
            this.patterns = patterns;
        }

        @Override
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
}
