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

/**
 * 通用工具类
 * Common Utility Class
 * 
 * 该类提供了一些通用的工具方法，如字符串处理、时间解析等
 * This class provides some common utility methods, such as string processing, time parsing, etc.
 */
public class MUtils {

    // 时间单位映射
    // Time unit mapping
    private static HashMap<String, Long> timeUnits;

    /**
     * 初始化时间单位映射
     * Initialize time unit mapping
     */
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

    /**
     * 判断字符串是否为空
     * Judge whether string is empty
     * 
     * @param s 字符串 string 是否为空 whether is empty
     */
    public static boolean isEmpty(String s) {
        return s == null || s.length() == 0;
    }

    /**
     * 判断字符串是否不为空
     * Judge whether string is not empty
     * 
     * @param s 字符串 string
     * @return 是否不为空 whether is not empty
     */
    public static boolean isNotEmpty(String s) {
        return !isEmpty(s);
    }

    /**
     * 判断字符串是否为空白
     * Judge whether string is blank
     * 
     * @param s 字符串 string
     * @return 是否为空白 whether is blank
     */
    public static boolean isBlank(String s) {
        return isEmpty(s) || s.trim().length() == 0;
    }

    /**
     * 判断字符串是否不为空白
     * Judge whether string is not blank
     * 
     * @param s 字符串 string
     * @return 是否不为空白 whether is not blank
     */
    public static boolean isNotBlank(String s) {
        return !isBlank(s);
    }

    /**
     * 解析时间字符串为毫秒
     * Parse time string to milliseconds
     * 
     * @param s 时间字符串，格式如 1ms 1s 1m 1h 1d 1M 1y time string, format like 1ms 1s 1m 1h 1d 1M 1y
     * @return 毫秒数 milliseconds
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

    /**
     * 截取字符串
     * Substring
     * 
     * @param s 字符串 string
     * @param start 开始位置 start position
     * @param end 结束位置 end position
     * @return 截取后的字符串 substring
     */
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

    /**
     * 首字母大写
     * Capitalize first letter
     * 
     * @param s 字符串 string
     * @return 首字母大写后的字符串 string with first letter capitalized
     */
    public static String upperCaseFirstOne(String s) {
        if (isEmpty(s)) {
            return s;
        }
        return s.substring(0, 1).toUpperCase() + s.substring(1);
    }

    /**
     * 首字母小写
     * Lowercase first letter
     * 
     * @param s 字符串 string
     * @return 首字母小写后的字符串 string with first letter lowercase
     */
    public static String lowerCaseFirstOne(String s) {
        if (isEmpty(s)) {
            return s;
        }
        return s.substring(0, 1).toLowerCase() + s.substring(1);
    }

    /**
     * MD5加密
     * MD5 encryption
     * 
     * @param s 字符串 string
     * @return MD5加密后的字符串 MD5 encrypted string
     */
    public static String md5(String s) {
        if (isEmpty(s)) {
            return s;
        }
        return DigestUtils.md5DigestAsHex(s.getBytes());

    }

    /**
     * 文件MD5加密
     * File MD5 encryption
     * 
     * @param file 文件 file
     * @return MD5加密后的字符串 MD5 encrypted string
     * @throws IOException 异常 IOException exception
     */
    public static String md5(MultipartFile file) throws IOException {
        if (file == null) {
            return null;
        }

        return DigestUtils.md5DigestAsHex(file.getBytes());

    }

    /**
     * 驼峰命名转换为下划线命名
     * Convert camel case to underscore case
     * 
     * @param s 驼峰命名的字符串 camel case string
     * @return 下划线命名的字符串 underscore case string
     */
    public static String mappingCamelCaseToUnderscore(String s) {
        if (isEmpty(s)) {
            return s;
        }

        Matcher matcher = Pattern.compile("[A-Z]").matcher(lowerCaseFirstOne(s));

        return matcher.replaceAll(arg -> "_" + arg.group().toLowerCase());

    }

    /**
     * 拼接处理器方法的URI
     * Concatenate handler method URI
     * 
     * @param handlerMethod 处理器方法 handler method
     * @return 拼接后的URI concatenated URI
     */
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

    /**
     * 获取处理器方法的HTTP方法
     * Get HTTP method of handler method
     * 
     * @param handlerMethod 处理器方法 handler method
     * @return HTTP方法，如 get、post、put、delete HTTP method, such as get, post, put, delete
     */
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
