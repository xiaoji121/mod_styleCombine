package com.alibaba.china.style.util;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPOutputStream;

import com.alibaba.china.style.file.FileDesc;

public class IOUtil {

    /**
     * ��ȡ�ļ��б�
     * 
     * @param file
     * @param fileList
     */
    public static void getFilesList(File file, List<File> fileList, FileFilter filter) {
        if (file == null || fileList == null || !file.exists()) {
            return;
        }
        if (file.isFile()) {
            return;
        }
        File[] fs = file.listFiles(filter);
        for (File f : fs) {
            if (f.isFile()) {
                fileList.add(f);
            }
            if (f.isDirectory()) {
                getFilesList(f, fileList, filter);
            }
        }
    }

    public static boolean writeString(File filePath, String str) {
        if (null == filePath || null == str) {
            return false;
        }

        boolean flag = false;
        BufferedWriter bw = null;
        try {
            bw = new BufferedWriter(new FileWriter(filePath));
            bw.write(str);
            flag = true;
        } catch (Exception e) {
            e.printStackTrace();
            flag = false;
        } finally {
            if (null != bw) {
                try {
                    bw.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return flag;
    }

    public static byte[] bytesRead(String filePath) {
        File f = new File(filePath);
        InputStream in = null;
        byte[] input = new byte[(int) f.length()];
        try {
            in = new FileInputStream(f);
            int r = in.read(input);
            if (r != input.length) {
                input = null;
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (null != in) {
                try {
                    in.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return input;
    }

    public static String stringRead(String filePath) {
        if (filePath == null) {
            return "";
        }
        StringBuilder buf = new StringBuilder();
        BufferedReader br = null;
        try {
            FileReader fr = new FileReader(filePath);
            br = new BufferedReader(fr);
            String sline = br.readLine();
            while (null != sline) {
                buf.append(sline);
                sline = br.readLine();
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (null != br) {
                try {
                    br.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        return buf.toString();
    }

    public static boolean writeVersionObject(File filePath, Object obj) {
        if (obj == null) {
            return false;
        }
        boolean flag = false;
        OutputStream os = null;
        ObjectOutput oo = null;
        try {
            os = new FileOutputStream(filePath);
            oo = new ObjectOutputStream(os);
            oo.writeObject(obj);
            flag = true;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (oo != null) {
                try {
                    oo.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return flag;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, FileDesc> getVersionObject(File filePath) {
        if (null == filePath || !filePath.exists()) {
            return null;
        }
        InputStream in = null;
        ObjectInput oi = null;
        try {
            in = new FileInputStream(filePath);
            oi = new ObjectInputStream(in);

            Object robj = oi.readObject();
            if (null == robj) {
                return null;
            }
            if (robj instanceof List) {
                return (Map<String, FileDesc>) robj;
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } finally {
            try {
                if (oi != null) {
                    oi.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    public static boolean gzipCompress(File dest, File source) {

        if (null == source || null == dest) {
            return false;
        }

        FilterOutputStream os = null;
        try {
            os = new GZIPOutputStream(new FileOutputStream(dest));
            os.write(bytesRead(source.getAbsolutePath()));
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } finally {
            if (null != os) {
                try {
                    os.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        return true;
    }
}
