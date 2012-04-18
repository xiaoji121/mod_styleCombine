package com.alibaba.china.style;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import com.alibaba.china.style.config.StyleConfig;
import com.alibaba.china.style.file.FileDesc;
import com.alibaba.china.style.util.IOUtil;
import com.alibaba.china.style.version.StyleVersion;
import com.alibaba.china.style.version.impl.StyleVersionImpl;

/**
 * @author Administrator
 */
public class StyleVersionProcessor {

    private StyleVersion          styleVersion = new StyleVersionImpl();

    private StyleConfig           pConfig;

    private Map<String, FileDesc> sourceFdMap  = null;

    public StyleVersionProcessor(StyleConfig pConfig){
        this.pConfig = pConfig;
    }

    public synchronized boolean execute() {
        if (null == sourceFdMap) {
            sourceFdMap = styleVersion.getStyleVersion(pConfig.getStyleVsSourceFilePath());
        }
        List<FileDesc> fileDescList = new CopyOnWriteArrayList<FileDesc>();
        boolean hasUpdate = styleVersion.diffAndCombine(fileDescList, sourceFdMap, pConfig);
        if (hasUpdate) {
            long start = 0;
            if (1 == pConfig.getDebugModel()) {
                start = System.currentTimeMillis();
            }
            File file = new File(pConfig.getStyleVsSourceFilePath());
            if (!file.exists()) {
                file.mkdirs();
            }
            // write styleVersion file of index
            StringBuilder path = new StringBuilder(pConfig.getStyleVsSourceFilePath());
            path.append(File.separator).append(StyleVersion.STYLE_VERSION_FILE_NAME);

            // CopyOnWriteArrayList unsupportedSort
            List<FileDesc> destList = new ArrayList<FileDesc>(fileDescList);
            Collections.sort(destList);

            file = new File(path.toString());
            boolean isBuilded = styleVersion.builderStyleVersion(file, destList);
            if (!isBuilded) {
                // FIXME: builder error add log
                return false;
            }
            // gzip compress
            File destFile = new File(path.toString() + ".gz");
            boolean isCompressed = IOUtil.gzipCompress(destFile, file);
            if (!isCompressed) {
                // FIXME: builder error add log
                return false;
            }
            boolean isSucess = false;
            path.append(StyleVersion.BYTE_STYLE_VERSION_EXT);
            File curFile = new File(path.toString());
            if (curFile.exists()) {
                // rename file to old
                File oldFile = new File(path.append("_old").toString());
                isSucess = curFile.renameTo(oldFile);
            }
            // wirte Map object byte to file
            Map<String, FileDesc> destFdMap = new HashMap<String, FileDesc>(destList.size());
            for (FileDesc fd : destList) {
                destFdMap.put(fd.getPath(), fd);
            }
            isSucess = IOUtil.writeVersionObject(curFile, destFdMap);
            if (isSucess) {
                sourceFdMap = destFdMap;
            }
            if (1 == pConfig.getDebugModel()) {
                long end = System.currentTimeMillis();
                System.out.println("ioWrite const time: " + ((end - start)) + " ms");
            }
            return isSucess;
        }
        return true;
    }

    public StyleConfig getpConfig() {
        return pConfig;
    }

    public void setpConfig(StyleConfig pConfig) {
        this.pConfig = pConfig;
    }
}
