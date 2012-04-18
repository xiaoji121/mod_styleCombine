package com.alibaba.china.style.util;

import java.util.ArrayList;
import java.util.List;

public final class StringUtil {

    public static boolean equals(String s1, String s2) {
        if (null == s1) {
            return s2 == null;
        }
        return s1.equals(s2);
    }

    public static String upperCaseFirstChar(String str) {
        if (null == str) {
            return str;
        }
        char[] dst = new char[str.length()];
        str.getChars(0, str.length(), dst, 0);
        dst[0] = Character.toUpperCase(dst[0]);
        return new String(dst);
    }

    public static List<String> stringToList(String str) {
        List<String> list = new ArrayList<String>();
        if (null == str) {
            return list;
        }

        String vs[] = str.split(",");
        for (String s : vs) {
            list.add(s);
        }
        return list;
    }
}
