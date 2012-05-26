package com.alibaba.china.style.util;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
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

    /**
     * @param fileName
     * @return
     */
    public static String fileNameOfDate(String fileName) {
        java.util.Calendar cd = Calendar.getInstance();

        DateFormat sdf = new SimpleDateFormat("yyyy_MM_dd_hh_mm");
        String date = sdf.format(cd.getTime());

        StringBuilder build = new StringBuilder();
        build.append(fileName).append("_").append(date);

        return build.toString();
    }

    public static void main(String args[]) {

        System.out.println(fileNameOfDate("hello"));

    }
}
