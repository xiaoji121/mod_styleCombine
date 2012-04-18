package com.alibaba.china.style.config;

import java.beans.BeanInfo;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.Properties;

public class StyleConfigParser {

    public void parserConfig(Object o, String filePath) throws Exception {
        if (null == o || null == filePath) {
            return;
        }
        File f = new File(filePath);
        if (!f.exists()) {
            return;
        }

        Properties prop = parserConfig(filePath);

        BeanInfo beanInfo = Introspector.getBeanInfo(o.getClass());

        PropertyDescriptor[] oDesc = beanInfo.getPropertyDescriptors();

        for (int i = 0; i < oDesc.length; i++) {
            String name = oDesc[i].getName();
            if ("class".equals(name)) {
                continue;
            }
            String arg = prop.getProperty(name);
            if (null == arg) {
                continue;
            }
            Method md = oDesc[i].getWriteMethod();
            if (null == md) {
                continue;
            }
            Class<?> type = oDesc[i].getPropertyType();
            if (type == arg.getClass()) {
                md.invoke(o, arg);
                continue;
            }
            if (type == Long.TYPE) {
                md.invoke(o, Long.valueOf(arg));
            }
            if (type == Integer.TYPE) {
                md.invoke(o, Integer.valueOf(arg));
            }
            if (type == Boolean.TYPE) {
                md.invoke(o, Boolean.valueOf(arg));
            }
        }
    }

    public String getConfigPath(Map<String, String> argsMap) {
        return argsMap.get("configPath");
    }

    protected Properties parserConfig(String filePath) {

        Properties ps = new Properties();
        try {
            ps.load(new FileInputStream(filePath));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return ps;
    }
}
