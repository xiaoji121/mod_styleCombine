package com.alibaba.china.style;

import java.util.HashMap;
import java.util.Map;

import com.alibaba.china.style.config.StyleConfig;
import com.alibaba.china.style.config.StyleConfigParser;
import com.alibaba.china.style.interval.TimerStart;

public class StyleMain {

    public static void main(String[] args) throws Exception {
        Map<String, String> argsMap = parserArgs(args);

        StyleConfigParser scp = new StyleConfigParser();
        StyleConfig pConfig = new StyleConfig();
        scp.parserConfig(pConfig, scp.getConfigPath(argsMap));
        StyleVersionProcessor svp = new StyleVersionProcessor(pConfig);

        TimerStart tstart = new TimerStart(svp);
        tstart.startTimer();
    }

    private static Map<String, String> parserArgs(String[] args) {
        Map<String, String> argsMap = new HashMap<String, String>();
        if (null == args) {
            return argsMap;
        }
        for (String s : args) {
            String[] exps = s.split("=");
            if (exps.length == 2) {
                argsMap.put(exps[0], exps[1]);
            }
            argsMap.put(s, s);
        }
        return argsMap;
    }
}
