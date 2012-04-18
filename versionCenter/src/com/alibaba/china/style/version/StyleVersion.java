package com.alibaba.china.style.version;

import java.io.File;
import java.util.List;
import java.util.Map;

import com.alibaba.china.style.config.StyleConfig;
import com.alibaba.china.style.file.FileDesc;

public interface StyleVersion {

    public static final String STYLE_VERSION_FILE_NAME = "styleVersion";
    public static final String BYTE_STYLE_VERSION_EXT  = ".bin";
    public static final String FILE_TYPE_CSS           = ".css";
    public static final String FILE_TYPE_JS            = ".js";

    public Map<String, FileDesc> getStyleVersion(String filePath);

    public boolean diffAndCombine(List<FileDesc> fileDescList, Map<String, FileDesc> source, StyleConfig pConfig);

    public boolean builderStyleVersion(File filePath, List<FileDesc> fileDescList);
}
