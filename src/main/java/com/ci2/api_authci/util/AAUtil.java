package com.ci2.api_authci.util;

import cn.hutool.core.util.IdUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.jwt.JWT;
import cn.hutool.jwt.JWTValidator;
import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.TypeReference;
import com.ci2.api_authci.exception.NotLoginException;
import com.ci2.api_authci.exception.PermDeniedException;
import com.ci2.api_authci.property.ApiAuthciProperty;
import com.fasterxml.jackson.annotation.JsonIgnore;
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
 * 该类提供了API鉴权相关的工具方法，包括token生成、用户信息获取等
 * This class provides utility methods for API authentication, including token generation, user information retrieval, etc.
 */
public class AAUtil {

    // Redis键前缀：用户ID对应的token
    // Redis key prefix: token corresponding to user ID
    private static final String ID_TOKEN_REDIS_KEY = "authci::id::";
    
    // Redis键前缀：token对应的用户数据
    // Redis key prefix: user data corresponding to token
    private static final String TOKEN_DATA_REDIS_KEY = "authci::token::";
    private static final String LOGIN_TYPE_DEFAULT = "default";

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
    private static RedisTemplate<String,Object> redisTemplate;

    private static RdUtil rdUtil;
    
    // 请求映射处理器
    // Request mapping handler
    private static RequestMappingHandlerMapping handlerMapping;

    // 数据包装器
    // Data wrapper
    private static DataWrapper<TokenData> dataWrapper;

    /**
     * 设置配置属性
     * Set configuration properties
     * 
     * @param apiAuthciProperty 配置属性
     * @param apiAuthciProperty configuration properties
     */
    public static void setApiAuthciProperty(ApiAuthciProperty apiAuthciProperty) {
        if (AAUtil.apiAuthciProperty != null) {
            throw new IllegalCallerException();
        }
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
        if (AAUtil.redisTemplate != null) {
            throw new IllegalCallerException();
        }
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
        if (AAUtil.dataWrapper != null) {
            throw new IllegalCallerException();
        }

        AAUtil.dataWrapper = dataWrapper;
    }

    public static void setRdUtil(RdUtil rdUtil) {
        if (AAUtil.dataWrapper != null) {
            throw new IllegalCallerException();
        }
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

    /**
     * 生成token
     * Generate token
     * 
     * @param loginId 登录ID
     * @param loginId login ID
     * @param loginType 登录类型
     * @param loginType login type
     * @return token字符串
     * @return token string
     */
    public static String getToken(Object loginId, String loginType,Map<String,Object> payload){

        // 构建payload
        // Build payload
        TokenData data = new TokenData();
        data.setLoginId(loginId).setLoginType(loginType)
                .setPayloadStr(JSON.toJSONString(payload));

        String dataJson = JSON.toJSONString(data);


        // 生成token
        // Generate token
        String token = generaToken(dataJson);

        // 存储token到Redis
        // Store token to Redis
        if (redisTemplate != null){

            RLock lock=null;
            try {
                lock = rdUtil.lock(loginId.toString());
                List<String> delKeys=new ArrayList<>();
                List<String> idKeys = getAllMatchKeyList(getLoginIdKeyPattern(loginId));
                idKeys.sort(Comparator.comparing(s -> s.substring(s.lastIndexOf(":") + 1)));

                if (idKeys.size() > apiAuthciProperty.getPerDeviceTypeAllowLoginCount()) {

                    int count=0;
                    String loginIdKey = getLoginIdKey(loginId);
                    for (int n = idKeys.size() - 1; n >= 0 ; n--) {
                        String idKey = idKeys.get(n);
                        if (idKey.startsWith(loginIdKey)) {
                            count++;

                            if (count>=apiAuthciProperty.getPerDeviceTypeAllowLoginCount()) {
                                idKeys.remove(n);
                                delKeys.add(idKey);

                            }
                        }


                    }
                }

                for (int i = idKeys.size()-apiAuthciProperty.getMaxAllowLoginDevices(); i >= 0; i--) {
                    delKeys.add(idKeys.get(i));
                }

                List<Object> delTokens = redisTemplate.opsForValue().multiGet(delKeys);
                if (delTokens != null && delTokens.size() > 0) {
                    delTokens.forEach(o ->
                            delKeys.add(getTokenKey(o)));
                }
                if (!delKeys.isEmpty()) {
                    redisTemplate.delete(delKeys);
                }


                Duration expiration = Duration.ofMillis(apiAuthciProperty.getExpiration());
                redisTemplate.opsForValue().set(getTokenKey(token), data, expiration);
                redisTemplate.opsForValue().set(getLoginIdKeyWithSn(loginId,data), token, expiration);

            } finally {
                if (lock!=null && lock.isLocked()) {
                    lock.unlock();
                }
            }



        }

        return token;



    }

    private static String getLoginIdKeyPattern(Object loginId) {
        return getLoginIdKey(loginId) + "::*";
    }

    public static List<String> getAllMatchKeyList(String pattern) {
        redisCheck();
        List<String> idKeys=new ArrayList<>();

        Cursor<String> cursor = redisTemplate.scan(
                ScanOptions.scanOptions()
                        .match(pattern)
                        .count(100)
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
    private static String getLoginIdKey(Object loginId) {
        return ID_TOKEN_REDIS_KEY + loginId+"::"+dataWrapper.getDeviceType();
    }

    private static String getLoginIdKeyWithSn(Object loginId, TokenData tokenData) {
        return getLoginIdKey(loginId)+"::"+tokenData.getSn();
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
                    .addPayloads(JSON.parseObject(payload,new TypeReference<Map<String, Object>>() {}))
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
        return getToken(loginId, LOGIN_TYPE_DEFAULT,null);
    }
    public static String getToken(Object loginId,Map<String,Object> payload) {
        return getToken(loginId, LOGIN_TYPE_DEFAULT,payload);
    }

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
    public static Object getLoginId(){
        return getTokenData().getLoginId();
    }
    
    /**
     * 获取登录ID（转换为Long）
     * Get login ID (convert to Long)
     * 
     * @return 登录ID
     * @return login ID
     */
    public static Long getLoginIdAsLong(){
        return Long.valueOf(getLoginId().toString());
    }

    /**
     * 获取登录ID（转换为String）
     * Get login ID (convert to String)
     * 
     * @return 登录ID
     * @return login ID
     */
    public static String getLoginIdAsString(){
        return getLoginId().toString();
    }

    /**
     * 获取登录类型
     * Get login type
     * 
     * @return 登录类型
     * @return login type
     */
    public static String getLoginType(){
        return getTokenData().getLoginType();
    }

    /**
     * 尝试获取登录ID（不抛出异常）
     * Try to get login ID (without throwing exception)
     * 
     * @return 登录ID，可能为null
     * @return login ID, may be null
     */
    public static Object tryGetLoginId(){
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
    public static String tryGetLoginType(){
        try {
            return getTokenData().getLoginType().toString();
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
    public static TokenData getTokenData(){
        // 先从数据包装器中获取
        // First get from data wrapper
        if (dataWrapper.getData() != null){
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
        TokenData data=null;
//        Map<String, Object> data = new HashMap<>();
        if (redisTemplate != null){
            // 从Redis中获取
            // Get from Redis
            data = (TokenData) redisTemplate.opsForValue().get(getTokenKey(token));


//            data=JSON.parseObject(JSON.toJSONString(result), TokenData.class);

        } else if (ApiAuthciProperty.TokenType.jwt.equals(apiAuthciProperty.getTokenType())) {
            // 从JWT中获取
            // Get from JWT
            JWT jwt = JWT.create().parse(token)
                    .setKey(apiAuthciProperty.getSecretKey().getBytes());
            JWTValidator.of(jwt).validateDate();
            JSONObject payloads = jwt.getPayloads();

            data=JSON.parseObject(JSON.toJSONString(payloads), TokenData.class);
        }
        
        // 检查数据是否为空
        // Check if data is empty
        if (data==null){
            throw new NotLoginException();
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
    public static String getRequestDeviceType(){

        UserAgent userAgent = UserAgent.parseUserAgentString(getRequest().getHeader("User-Agent"));
        return userAgent.getOperatingSystem().getDeviceType().getName();
    }

    public static HttpServletRequest getRequest() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        HttpServletRequest request = attributes.getRequest();
        return request;
    }

    private static void redisCheck(){
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
    public static void kickout(Object loginId){
        redisCheck();

        List<String> keys = getAllMatchKeyList(getLoginIdKeyPattern(loginId));
        List<Object> tokens = redisTemplate.opsForValue().multiGet(keys);

        if (tokens != null && tokens.size() > 0) {
            tokens.forEach(token -> {keys.add(getTokenKey(token));});
        }
        redisTemplate.delete(keys);

    }

    public static void kickout(String token){
        redisCheck();

        String tokenKey = getTokenKey(token);
        TokenData data = (TokenData) redisTemplate.opsForValue().get(tokenKey);

//        if (result == null){
//            return;
//        }
//        TokenData data = JSON.parseObject(JSON.toJSONString(result), TokenData.class);
        List<String> delKeys = List.of(tokenKey, getLoginIdKeyWithSn(data.getLoginId(), data));

        redisTemplate.delete(delKeys);

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
    public static void logout(){
        kickout(getRequestToken());
        dataWrapper.setData(null);
    }

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
            if (data!=null){
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
     */
    @Data
    public static class DataWrapper<T> {
        // 存储的数据
        // Stored data
        T data;
        String token;
        String deviceType;

        public String getToken() {
            if (token == null) {
                return token=getRequestToken();
            }
            return token;
        }

        public String getDeviceType() {
            if (deviceType == null) {
                return deviceType=getRequestDeviceType();
            }
            return deviceType;
        }
    }

    @Data
    @Accessors(chain = true)
    public static class TokenData{


        @JsonIgnore(value = true)
        String token;

        Object loginId;
        String loginType;
        String sn = IdUtil.getSnowflakeNextId()+"";
        Map<String, Object> payload;
        String payloadStr;

        public void setPayloadStr(String payloadStr) {
            this.payloadStr = payloadStr;
            payload= JSON.parseObject(payloadStr, new TypeReference<Map<String, Object>>() {});
        }
    }



}
