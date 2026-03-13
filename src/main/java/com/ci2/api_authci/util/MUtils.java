package com.ci2.api_authci.util;


import org.springframework.util.DigestUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MUtils {

    private static HashMap<String, Long> timeUnits;

    private static void initTimeUnits() {
        timeUnits = new HashMap<>();
        timeUnits.put("ms", 1L);
        timeUnits.put("s", timeUnits.get("ms") * 1000);
        timeUnits.put("m", timeUnits.get("s") * 60);
        timeUnits.put("h", timeUnits.get("m") * 60);
        timeUnits.put("d", timeUnits.get("h") * 24);
        timeUnits.put("M", timeUnits.get("d") * 30);
        timeUnits.put("y", timeUnits.get("d") * 365);
    }


    public static boolean isEmpty(String s) {
        return s == null || s.length() == 0;
    }

    public static boolean isNotEmpty(String s) {
        return !isEmpty(s);
    }

    public static boolean isBlank(String s) {
        return isEmpty(s) || s.trim().length() == 0;
    }

    public static boolean isNotBlank(String s) {
        return !isBlank(s);
    }

    /**
     * @param s format 1ms 1s 1m 1h 1d 1M 1y
     * @return
     */
    public static long parseTimeToMs(String s) {

        if (isEmpty(s)) {
            throw new RuntimeException("not a format time");
        }
        String[] timeS = s.replaceAll("(\\d+)(\\S{1,2})", "$1-$2").split("-");

        if (timeUnits == null) {
            initTimeUnits();
        }
        Long unit = timeUnits.get(timeS[1].toLowerCase());
        return Long.parseLong(timeS[0]) * unit;
    }

    public static String substring(String s, int start, int end) {

        if (isEmpty(s)) {
            return "";
        }

        int len = end - start;
        if (len < 0) {
            throw new RuntimeException("illegal param");
        }

        if (start >= s.length()) {
            return "";
        }
        if (end > s.length() || s.length() - start < len) {
            return s.substring(start);
        }

        return s.substring(start, end);

    }

    public static String upperCaseFirstOne(String s) {
        if (isEmpty(s)) {
            return s;
        }
        return s.substring(0, 1).toUpperCase() + s.substring(1);
    }

    public static String lowerCaseFirstOne(String s) {
        if (isEmpty(s)) {
            return s;
        }
        return s.substring(0, 1).toLowerCase() + s.substring(1);
    }

    public static String md5(String s) {
        if (isEmpty(s)) {
            return s;
        }
        return DigestUtils.md5DigestAsHex(s.getBytes());

    }


    public static String md5(MultipartFile file) throws IOException {

        if (file == null) {
            return null;
        }

        return DigestUtils.md5DigestAsHex(file.getBytes());


    }

    public static String mappingCamelCaseToUnderscore(String s) {
        if (isEmpty(s)) {
            return s;
        }

        Matcher matcher = Pattern.compile("[A-Z]").matcher(lowerCaseFirstOne(s));

        return matcher.replaceAll(arg -> "_" + arg.group().toLowerCase());


    }


    public static String concatHandlerMethodUri(HandlerMethod handlerMethod) {

        if (handlerMethod == null) {
            return "";
        }

        String[][] uris = new String[2][];
        uris[0] = handlerMethod.getBeanType().getAnnotation(RequestMapping.class).value();
        uris[1] = handlerMethod.getMethodAnnotation(RequestMapping.class).value();

        StringBuilder sb = new StringBuilder();


        Arrays.stream(uris).flatMap(list -> Arrays.stream(list)).forEach(u -> {
            if (!u.startsWith("/")) {
                sb.append("/");
            }
            sb.append(u);
        });

        return sb.toString();


    }

    public static String getHandlerMethodMethod(HandlerMethod handlerMethod) {
        if (handlerMethod == null) {
            return "";
        }
        String name = "";
        if (handlerMethod.getMethodAnnotation(GetMapping.class) != null) {
            name = "get";
        } else if (handlerMethod.getMethodAnnotation(PostMapping.class) != null) {
            name = "post";
        } else if (handlerMethod.getMethodAnnotation(PutMapping.class) != null) {
            name = "put";
        } else if (handlerMethod.getMethodAnnotation(DeleteMapping.class) != null) {
            name = "delete";
        } else {
            return "";
        }


        return name;


    }


}
