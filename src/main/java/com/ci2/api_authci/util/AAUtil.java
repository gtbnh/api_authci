package com.ci2.api_authci.util;

import cn.hutool.core.util.IdUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.jwt.JWT;
import cn.hutool.jwt.JWTValidator;
import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.TypeReference;
import com.ci2.api_authci.exception.NotLoginException;
import com.ci2.api_authci.exception.PermDeniedException;
import com.ci2.api_authci.intf.PermValidator;
import com.ci2.api_authci.property.ApiAuthciProperty;
import eu.bitwalker.useragentutils.UserAgent;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Data;
import lombok.experimental.Accessors;
import org.redisson.api.RLock;
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.time.Duration;
import java.util.*;

/**
 * API 鉴权工具类
 * API Authentication Utility Class
 * 
 * 该类提供了API鉴权相关的工具方法，包括token生成、用户信息获取、权限验证等
 * This class provides utility methods for API authentication, including token generation, user information retrieval, permission verification, etc.
 */
public class AAUtil {

    // Redis键前缀：用户ID对应的token
    // Redis key prefix: token corresponding to user ID
    private static final String ID_TOKEN_REDIS_KEY = "authci::id::";
    
    // Redis键前缀：token对应的用户数据
    // Redis key prefix: user data corresponding to token
    private static final String TOKEN_DATA_REDIS_KEY = "authci::token::";
    
    // 默认登录类型
    // Default login type
    private static final String LOGIN_TYPE_DEFAULT = "default";

    // Redis锁键前缀
    // Redis lock key prefix
    private static final String LOCK_REDIS_KEY = "authci::lock::";

    // 登录ID键名
    // Login ID key name
    private static final String ID_KEY = "loginId";
    
    // 登录类型键名
    // Login type key name
    private static final String LOGIN_TYPE_KEY = "loginType";

    // 配置属性
    // Configuration properties
    private static ApiAuthciProperty apiAuthciProperty;
    
    // Redis模板
    // Redis template
    private static RedisTemplate<String, Object> redisTemplate;

    // Redis分布式锁工具
    // Redis distributed lock utility
    private static RdUtil rdUtil;
    
    // 请求映射处理器
    // Request mapping handler
    private static RequestMappingHandlerMapping handlerMapping;

    // 数据包装器
    // Data wrapper
    private static DataWrapper<TokenData> dataWrapper;

    private static PermValidator permValidator;

    private static volatile boolean isInit = false;

    public static void setPermValidator(PermValidator permValidator) {
        checkInit();
        AAUtil.permValidator = permValidator;
    }

    /**
     * 设置配置属性
     * Set configuration properties
     * 
     * @param apiAuthciProperty 配置属性
     * @param apiAuthciProperty configuration properties
     */
    public static void setApiAuthciProperty(ApiAuthciProperty apiAuthciProperty) {
        checkInit();
        AAUtil.apiAuthciProperty = apiAuthciProperty;
    }

    /**
     * 设置Redis模板
     * Set Redis template
     * 
     * @param redisTemplate Redis模板
     * @param redisTemplate Redis template
     */
    public static void setRedisTemplate(RedisTemplate redisTemplate) {
        checkInit();
        AAUtil.redisTemplate = redisTemplate;
    }

    /**
     * 设置数据包装器
     * Set data wrapper
     * 
     * @param dataWrapper 数据包装器
     * @param dataWrapper data wrapper
     */
    public static void setDataWrapper(DataWrapper<TokenData> dataWrapper) {
        checkInit();
        AAUtil.dataWrapper = dataWrapper;
    }

    /**
     * 设置Redis分布式锁工具
     * Set Redis distributed lock utility
     * 
     * @param rdUtil Redis分布式锁工具
     * @param rdUtil Redis distributed lock utility
     */
    public static void setRdUtil(RdUtil rdUtil) {
        checkInit();
        AAUtil.rdUtil = rdUtil;
    }

    /**
     * 设置请求映射处理器
     * Set request mapping handler
     * 
     * @param handlerMapping 请求映射处理器
     * @param handlerMapping request mapping handler
     */
    public static void setHandlerMapping(RequestMappingHandlerMapping handlerMapping) {
        AAUtil.handlerMapping = handlerMapping;
    }

    public static void postConstr() {
        isInit = true;
    }

    public static void checkInit() {
        if (isInit) {
            throw new IllegalCallerException();
        }
    }

    /**
     * 生成token
     * Generate token
     * 
     * @param loginId 登录ID
     * @param loginId login ID
     * @param loginType 登录类型
     * @param loginType login type
     * @param payload 额外载荷数据
     * @param payload additional payload data
     * @return token字符串
     * @return token string
     */
    public static String getToken(Object loginId, String loginType, Map<String, Object> payload) {
        // 构建payload
        // Build payload
        TokenData data = new TokenData();
        data.setLoginId(loginId).setLoginType(loginType)
                .setDeviceType(dataWrapper.getDeviceType())
                .setPayload(payload);

        String dataJson = JSON.toJSONString(data);

        // 生成token
        // Generate token
        String token = generaToken(dataJson);

        // 存储token到Redis
        // Store token to Redis
        if (redisTemplate != null) {
            RLock lock = null;
            try {
                // 获取分布式锁
                // Get distributed lock
                lock = rdUtil.lock(getLockKey(loginId));
                List<String> delKeys = new ArrayList<>();
                List<String> idKeys = getAllMatchKeyList(getLoginIdKeyPattern(loginId));
                // 按顺序排序键
                // Sort keys in order
                idKeys.sort(Comparator.comparing(s -> s.substring(s.lastIndexOf(":") + 1)));

                // 处理每设备类型登录数量限制
                // Handle per device type login count limit
                if (idKeys.size() > apiAuthciProperty.getPerDeviceTypeAllowLoginCount()) {
                    int count = 0;
                    String loginIdKey = getBasicLoginIdWithDTKey(loginId);
                    for (int n = idKeys.size() - 1; n >= 0; n--) {
                        String idKey = idKeys.get(n);
                        if (idKey.startsWith(loginIdKey)) {
                            count++;
                            if (count >= apiAuthciProperty.getPerDeviceTypeAllowLoginCount()) {
                                idKeys.remove(n);
                                delKeys.add(idKey);
                            }
                        }
                    }
                }

                // 处理最大登录设备数限制
                // Handle maximum login devices limit
                for (int i = idKeys.size() - apiAuthciProperty.getMaxAllowLoginDevices(); i >= 0; i--) {
                    delKeys.add(idKeys.get(i));
                }

                // 获取要删除的token
                // Get tokens to delete
                List<Object> delTokens = redisTemplate.opsForValue().multiGet(delKeys);
                if (delTokens != null && delTokens.size() > 0) {
                    delTokens.forEach(o ->
                            delKeys.add(getTokenKey(o)));
                }
                // 删除过期的键
                // Delete expired keys
                if (!delKeys.isEmpty()) {
                    redisTemplate.delete(delKeys);
                }

                // 存储新token
                // Store new token
                if (apiAuthciProperty.getExpiration() != -1) {
                    Duration expiration = Duration.ofMillis(apiAuthciProperty.getExpiration());
                    redisTemplate.opsForValue().set(getTokenKey(token), data, expiration);
                    redisTemplate.opsForValue().set(parseToLoginIdKey( data), token, expiration);
                } else {
                    redisTemplate.opsForValue().set(getTokenKey(token), data);
                    redisTemplate.opsForValue().set(parseToLoginIdKey( data), token);
                }

            } finally {
                // 释放锁
                // Release lock
                if (lock != null && lock.isLocked()) {
                    lock.unlock();
                }
            }
        }

        return token;
    }

    /**
     * 获取锁的键
     * Get lock key
     * 
     * @param loginId 登录ID
     * @param loginId login ID
     * @return 锁的键
     * @return lock key
     */
    private static String getLockKey(Object loginId) {
        return LOCK_REDIS_KEY + loginId.toString();
    }

    /**
     * 获取登录ID键的模式
     * Get login ID key pattern
     * 
     * @param loginId 登录ID
     * @param loginId login ID
     * @return 键的模式
     * @return key pattern
     */
    private static String getLoginIdKeyPattern(Object loginId) {
        return getBasicLoginIdKeySb(loginId).append("::*").toString();
    }

    /**
     * 获取所有匹配的键列表
     * Get all matching key list
     * 
     * @param pattern 键的模式
     * @param pattern key pattern
     * @return 匹配的键列表
     * @return matching key list
     */
    public static List<String> getAllMatchKeyList(String pattern) {
        redisCheck();
        List<String> idKeys = new ArrayList<>();

        // 使用Redis的scan命令获取匹配的键
        // Use Redis scan command to get matching keys
        Cursor<String> cursor = redisTemplate.scan(
                ScanOptions.scanOptions()
                        .match(pattern)
                        .count(apiAuthciProperty.getMaxAllowLoginDevices())
                        .build()
        );

        while (cursor.hasNext()) {
            String key = cursor.next();
            if (key != null) {
                idKeys.add(key);
            }
        }

        return idKeys;
    }

    /**
     * 获取用户ID对应的Redis键
     * Get Redis key for user ID
     * 
     * @param loginId 登录ID
     * @param loginId login ID
     * @return Redis键
     * @return Redis key
     */
    private static String getBasicLoginIdWithDTKey(Object loginId) {
        return getBasicLoginIdWithDTKeySb(loginId).toString();
    }

    /**
     * 获取基本的登录ID键构建器
     * Get basic login ID key builder
     * 
     * @param loginId 登录ID
     * @param loginId login ID
     * @return 键构建器
     * @return key builder
     */
    private static StringBuilder getBasicLoginIdKeySb(Object loginId) {
        StringBuilder sb = new StringBuilder(ID_TOKEN_REDIS_KEY);
        return sb.append(loginId);
    }

    /**
     * 获取登录ID键构建器
     * Get login ID key builder
     * 
     * @param loginId 登录ID
     * @param loginId login ID
     * @return 键构建器
     * @return key builder
     */
    private static StringBuilder getBasicLoginIdWithDTKeySb(Object loginId) {
        return getBasicLoginIdKeySb(loginId).append("::").append(dataWrapper.getDeviceType());
    }


    /**
     * 生成token
     * Generate token
     * 
     * @param payload 载荷数据
     * @param payload payload data
     * @return token字符串
     * @return token string
     */
    private static String generaToken(String payload) {
        if (ApiAuthciProperty.TokenType.jwt.equals(apiAuthciProperty.getTokenType())) {
            // 生成JWT token
            // Generate JWT token
            String token = JWT.create()
                    .setKey(apiAuthciProperty.getSecretKey().getBytes())
                    .setExpiresAt(new Date(System.currentTimeMillis() + apiAuthciProperty.getExpiration()))
                    .addPayloads(JSON.parseObject(payload, new TypeReference<Map<String, Object>>() { }))
                    .sign();
            return token;
        } else if (ApiAuthciProperty.TokenType.uuid.equals(apiAuthciProperty.getTokenType())) {
            // 生成UUID token
            // Generate UUID token
            return UUID.randomUUID().toString();
        }

        throw new IllegalCallerException();
    }

    /**
     * 生成token（使用默认登录类型）
     * Generate token (using default login type)
     * 
     * @param loginId 登录ID
     * @param loginId login ID
     * @return token字符串
     * @return token string
     */
    public static String getToken(Object loginId) {
        return getToken(loginId, LOGIN_TYPE_DEFAULT, null);
    }

    /**
     * 生成token（使用默认登录类型和自定义载荷）
     * Generate token (using default login type and custom payload)
     * 
     * @param loginId 登录ID
     * @param loginId login ID
     * @param payload 额外载荷数据
     * @param payload additional payload data
     * @return token字符串
     * @return token string
     */
    public static String getToken(Object loginId, Map<String, Object> payload) {
        return getToken(loginId, LOGIN_TYPE_DEFAULT, payload);
    }

    /**
     * 获取token中的载荷数据
     * Get payload data from token
     * 
     * @return 载荷数据
     * @return payload data
     */
    public static Map<String, Object> getPayload() {
        return getTokenData().getPayload();
    }

    /**
     * 获取登录ID
     * Get login ID
     * 
     * @return 登录ID
     * @return login ID
     */
    public static Object getLoginId() {
        return getTokenData().getLoginId();
    }

    /**
     * 获取登录ID（转换为Long）
     * Get login ID (convert to Long)
     * 
     * @return 登录ID
     * @return login ID
     */
    public static Long getLoginIdAsLong() {
        return Long.valueOf(getLoginId().toString());
    }

    /**
     * 获取登录ID（转换为String）
     * Get login ID (convert to String)
     * 
     * @return 登录ID
     * @return login ID
     */
    public static String getLoginIdAsString() {
        return getLoginId().toString();
    }

    /**
     * 获取登录类型
     * Get login type
     * 
     * @return 登录类型
     * @return login type
     */
    public static String getLoginType() {
        return getTokenData().getLoginType();
    }

    /**
     * 尝试获取登录ID（不抛出异常）
     * Try to get login ID (without throwing exception)
     * 
     * @return 登录ID，可能为null
     * @return login ID, may be null
     */
    public static Object tryGetLoginId() {
        try {
            return getTokenData().getLoginId();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 尝试获取登录类型（不抛出异常）
     * Try to get login type (without throwing exception)
     * 
     * @return 登录类型，默认为"default"
     * @return login type, default is "default"
     */
    public static String tryGetLoginType() {
        try {
            return getTokenData().getLoginType();
        } catch (Exception e) {
            return LOGIN_TYPE_DEFAULT;
        }
    }

    /**
     * 获取token数据
     * Get token data
     * 
     * @return token数据
     * @return token data
     */
    public static TokenData getTokenData() {
        // 先从数据包装器中获取
        // First get from data wrapper
        if (dataWrapper.getData() != null) {
            return dataWrapper.getData();
        }

        // 获取请求中的token
        // Get token from request
        String token = getRequestToken();
        if (MUtils.isBlank(token)) {
            throw new PermDeniedException("token is empty");
        }

        // 构建token数据
        // Build token data
        TokenData data = null;
        if (redisTemplate != null) {
            // 从Redis中获取
            // Get from Redis
            String tokenKey = getTokenKey(token);
            data = (TokenData) redisTemplate.opsForValue().get(tokenKey);
            if (data != null) {
                Object record = redisTemplate.opsForValue().get(parseToLoginIdKey(data));
                if (record == null) {

                    redisTemplate.delete(tokenKey);
                    throw new NotLoginException("invalid token:"+token);
                }
            }

        } else if (ApiAuthciProperty.TokenType.jwt.equals(apiAuthciProperty.getTokenType())) {
            // 从JWT中获取
            // Get from JWT
            JWT jwt = JWT.create().parse(token)
                    .setKey(apiAuthciProperty.getSecretKey().getBytes());
            JWTValidator.of(jwt).validateDate();
            JSONObject payloads = jwt.getPayloads();

            data = JSON.parseObject(JSON.toJSONString(payloads), TokenData.class);
        }

        // 检查数据是否为空
        // Check if data is empty
        if (data == null) {
            throw new NotLoginException("non-existent token:"+token);
        }

        // 存储到数据包装器中
        // Store to data wrapper
        dataWrapper.setData(data);
        return data;
    }

    /**
     * 获取请求中的token
     * Get token from request
     * 
     * @return token字符串
     * @return token string
     */
    public static String getRequestToken() {
        String token = getRequest().getHeader(apiAuthciProperty.getHeaders().getToken());
        return token;
    }

    /**
     * 获取请求设备类型
     * Get request device type
     * 
     * @return 设备类型
     * @return device type
     */
    public static String getRequestDeviceType() {
        UserAgent userAgent = UserAgent.parseUserAgentString(getRequest().getHeader("User-Agent"));
        return userAgent.getOperatingSystem().getDeviceType().getName();
    }

    /**
     * 获取当前HTTP请求
     * Get current HTTP request
     * 
     * @return HTTP请求
     * @return HTTP request
     */
    public static HttpServletRequest getRequest() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        HttpServletRequest request = attributes.getRequest();
        return request;
    }

    /**
     * 检查Redis是否存在
     * Check if Redis exists
     */
    private static void redisCheck() {
        if (redisTemplate == null) {
            throw new IllegalCallerException("call this method must have a redis");
        }
    }

    /**
     * 踢出用户（使其登录失效）
     * Kick out user (make login invalid)
     * 
     * @param loginId 登录ID
     * @param loginId login ID
     */
    public static void kickout(Object loginId) {
        redisCheck();

        List<String> keys = getAllMatchKeyList(getLoginIdKeyPattern(loginId));
        List<Object> tokens = redisTemplate.opsForValue().multiGet(keys);

        if (tokens != null && tokens.size() > 0) {
            tokens.forEach(token -> {keys.add(getTokenKey(token));});
        }
        redisTemplate.delete(keys);
    }

    /**
     * 踢出用户（通过token使其登录失效）
     * Kick out user (make login invalid by token)
     * 
     * @param token token字符串
     * @param token token string
     */
    public static void kickoutByToken(String token) {
        redisCheck();

        String tokenKey = getTokenKey(token);
        TokenData data = (TokenData) redisTemplate.opsForValue().get(tokenKey);
        if (data == null) {
            return;
        }

        List<String> delKeys = List.of(tokenKey, parseToLoginIdKey(data));

        redisTemplate.delete(delKeys);
    }
    // full
    public static String parseToLoginIdKey(TokenData data) {
        return getBasicLoginIdKeySb(data.getLoginId())
                .append("::").append(data.getDeviceType())
                .append("::").append(data.getSn()).toString();
    }

    /**
     * 获取token对应的Redis键
     * Get Redis key for token
     * 
     * @param token token字符串
     * @param token token string
     * @return Redis键
     * @return Redis key
     */
    private static String getTokenKey(Object token) {
        return TOKEN_DATA_REDIS_KEY + token;
    }

    /**
     * 登出
     * Logout
     */
    public static void logout() {
        kickoutByToken(getRequestToken());
        dataWrapper.setData(null);
    }

    /**
     * 获取用户的所有登录信息
     * Get all login information of user
     * 
     * @param loginId 登录ID
     * @param loginId login ID
     * @return 登录信息列表
     * @return login information list
     */
    public static List<TokenData> getAllLoginInfo(Object loginId) {
        List<String> keys = getAllMatchKeyList(getLoginIdKeyPattern(loginId));
        List<Object> tokens = redisTemplate.opsForValue().multiGet(keys);
        if (tokens == null || tokens.size() == 0) {
            return List.of();
        }
        List<String> tokenKeys = tokens.stream().map(AAUtil::getTokenKey).toList();

        List results = redisTemplate.opsForValue().multiGet(tokenKeys);
        if (results == null || results.size() == 0) {
            return List.of();
        }

        List<TokenData> dataList = results;
        for (int i = 0; i < tokenKeys.size(); i++) {
            TokenData data = dataList.get(i);
            String token = tokenKeys.get(i);
            if (data != null) {
                data.setToken(token);
            }
        }

        return dataList;
    }

    /**
     * 获取所有API权限
     * Get all API permissions
     * 
     * @return 权限列表
     * @return permission list
     */
    public static List<String> getAllApiPerms() {
        List<String> perms = new ArrayList<>();

        if (handlerMapping == null) {
            return perms;
        }

        // 遍历所有处理器方法，生成权限字符串
        // Traverse all handler methods, generate permission strings
        handlerMapping.getHandlerMethods()
                .values().forEach(handler -> {
                    perms.add(MUtils.getHandlerMethodMethod(handler) + ":"
                            + MUtils.concatHandlerMethodUri(handler));
                });

        return perms;
    }

    /**
     * 数据包装器类
     * Data wrapper class
     * 
     * 用于存储请求级别的数据，如token、设备类型等
     * Used to store request-level data, such as token, device type, etc.
     */
    @Data
    public static class DataWrapper<T> {
        // 存储的数据
        // Stored data
        T data;
        // token字符串
        // token string
        String token;
        // 设备类型
        // device type
        String deviceType;

        /**
         * 获取token
         * Get token
         * 
         * @return token字符串
         * @return token string
         */
        public String getToken() {
            if (token == null) {
                return token = getRequestToken();
            }
            return token;
        }

        /**
         * 获取设备类型
         * Get device type
         * 
         * @return 设备类型
         * @return device type
         */
        public String getDeviceType() {
            if (deviceType == null) {
                return deviceType = getRequestDeviceType();
            }
            return deviceType;
        }
    }

    /**
     * Token数据类
     * Token data class
     * 
     * 用于存储token相关的数据，如登录ID、登录类型、额外载荷等
     * Used to store token-related data, such as login ID, login type, additional payload, etc.
     */
    @Data
    @Accessors(chain = true)
    public static class TokenData {
        // token字符串
        // token string
        String token;

        // 登录ID
        // login ID
        Object loginId;
        // 登录类型
        // login type
        String loginType;
        // 序列号
        // serial number
        String sn = IdUtil.getSnowflakeNextId() + "";

        String deviceType;
        // 额外载荷数据
        // additional payload data
        Map<String, Object> payload;

    }

}
