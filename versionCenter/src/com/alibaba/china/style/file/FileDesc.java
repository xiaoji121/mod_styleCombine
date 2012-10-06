package com.alibaba.china.style.file;

import java.io.Serializable;

import com.alibaba.china.style.util.StringUtil;

/**
 * @author Administrator
 */
public class FileDesc implements Serializable, Comparable<FileDesc> {

    /**
     * 
     */
    private static final long serialVersionUID = 7186030185483971823L;

    private String            path;

    private String            type;

    private long              size;

    private long              lastModified;

    private String            version;

    private String            content;

    public FileDesc(){
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public long getSize() {
        return size;
    }

    public void setSize(long size) {
        this.size = size;
    }

    public long getLastModified() {
        return lastModified;
    }

    public void setLastModified(long lastModified) {
        this.lastModified = lastModified;
    }
    
    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    @Override
    public int hashCode() {
        int prime = 33;
        int result = 1;
        result = prime * result + (path == null ? 0 : path.hashCode());
        result = prime * result + (type == null ? 0 : type.hashCode());
        result = prime * result + (version == null ? 0 : version.hashCode());
        result = prime * result + (int) (size >>> 32);
        result = prime * result + (int) (lastModified >>> 32);
        return result;
    }

    @Override
    public boolean equals(Object obj) {

        if (null == obj) {
            return false;
        }
        if (!(obj instanceof FileDesc)) {
            return false;
        }

        FileDesc fd = (FileDesc) obj;

        if (!StringUtil.equals(fd.path, this.path)) {
            return false;
        }

        if (!StringUtil.equals(fd.type, this.type)) {
            return false;
        }

        if (!StringUtil.equals(fd.version, this.version)) {
            return false;
        }

        if (fd.size != this.size) {
            return false;
        }

        return true;
    }

    @Override
    public int compareTo(FileDesc o) {
        return this.path.compareTo(o.getPath());
    }

    @Override
    public String toString() {
        StringBuilder buf = new StringBuilder();
        buf.append("path:").append(path).append("\n");
        buf.append("type:").append(type).append("\n");
        buf.append("size:").append(size).append("\n");
        buf.append("lastModified:").append(lastModified).append("\n");
        buf.append("version:").append(version).append("\n");
        return buf.toString();
    }
}
