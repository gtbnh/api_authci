package com.ci2.api_authci.util;

import cn.hutool.json.JSONObject;
import cn.hutool.jwt.JWT;
import cn.hutool.jwt.JWTValidator;
import com.ci2.api_authci.exception.NotLoginException;
import com.ci2.api_authci.exception.PermDeniedException;
import com.ci2.api_authci.property.ApiAuthciProperty;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Data;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.time.Duration;
import java.util.*;

public class AAUtil {

    private static final String ID_TOKEN_REDIS_KEY = "authci::id::";
    private static final String TOKEN_DATA_REDIS_KEY = "authci::token::";
    private static final String ID_KEY = "loginId";
    private static final String LOGIN_TYPE_KEY = "loginType";

    private static ApiAuthciProperty apiAuthciProperty;
    private static RedisTemplate redisTemplate;
    private static RequestMappingHandlerMapping handlerMapping;

    private static DataWrapper dataWrapper;

    public static void setApiAuthciProperty(ApiAuthciProperty apiAuthciProperty) {
        if (AAUtil.apiAuthciProperty != null) {
            throw new IllegalCallerException();
        }
        AAUtil.apiAuthciProperty = apiAuthciProperty;
    }

    public static void setRedisTemplate(RedisTemplate redisTemplate) {
        if (AAUtil.redisTemplate != null) {
            throw new IllegalCallerException();
        }
        AAUtil.redisTemplate = redisTemplate;
    }

    public static void setDataWrapper(DataWrapper dataWrapper) {
        if (AAUtil.dataWrapper != null) {
            throw new IllegalCallerException();
        }
        AAUtil.dataWrapper = dataWrapper;
    }

    public static void setHandlerMapping(RequestMappingHandlerMapping handlerMapping) {
        AAUtil.handlerMapping = handlerMapping;
    }

    public static String getToken(Object loginId, String loginType){

        Object oldToken;
        if (apiAuthciProperty.isAllowMultiDeviceLogin() && redisTemplate!=null){

            oldToken = redisTemplate.opsForValue().get(getIdKey(loginId));
            if (oldToken != null){
                return oldToken.toString();
            }

        }

        HashMap<String, Object> map = new HashMap<>();
        map.put(ID_KEY, loginId);
        map.put(LOGIN_TYPE_KEY, loginType);

        String token = generaToken(map);

        if (redisTemplate!=null){
            oldToken = redisTemplate.opsForValue().get(getIdKey(loginId));
            if (oldToken!=null){
                redisTemplate.delete(getTokenKey(oldToken));
            }
            Duration expiration = Duration.ofMillis(apiAuthciProperty.getExpiration());
            redisTemplate.opsForValue().set(getIdKey(loginId),token, expiration);

            redisTemplate.opsForValue().set(getTokenKey(token),map,expiration);

        }
        return token;
    }



    private static String getIdKey(Object loginId) {
        return ID_TOKEN_REDIS_KEY + loginId;
    }

    private static String generaToken( Map<String,Object> payload) {

        if (ApiAuthciProperty.TokenType.jwt.equals(apiAuthciProperty.getTokenType())) {

            String token = JWT.create()
                    .setKey(apiAuthciProperty.getSecretKey().getBytes())
                    .setExpiresAt(new Date(System.currentTimeMillis() + apiAuthciProperty.getExpiration()))
                    .addPayloads(payload)
                    .sign();
            return token;
        }else if (ApiAuthciProperty.TokenType.uuid.equals(apiAuthciProperty.getTokenType())) {
            return UUID.randomUUID().toString();
        }

        throw new IllegalCallerException();
    }

    public static String getToken(Object loginId) {
        return getToken(loginId,"default");
    }

    public static Object getLoginId(){
        return getTokenData().get(ID_KEY);
    }
    public static Long getLoginIdAsLong(){
        return Long.valueOf(getLoginId().toString());
    }

    public static String getLoginIdAsString(){
        return getLoginId().toString();
    }

    public static String getLoginType(){
        return getTokenData().get(LOGIN_TYPE_KEY).toString();
    }

    public static Object tryGetLoginId(){
        try {
            return getTokenData().get(ID_KEY);
        } catch (Exception e) {
            return null;
        }
    }

    public static String tryGetLoginType(){
        try {
            return getTokenData().get(LOGIN_TYPE_KEY).toString();
        }catch (Exception e){
            return "default";
        }
    }

    private static Map<String,Object> getTokenData(){

        if (dataWrapper.getData()!=null){
            return dataWrapper.getData();
        }

        String token = getRequestToken();
        if (MUtils.isBlank(token)) {
            throw new PermDeniedException("token is empty");
        }
        Map<String,Object> data = new HashMap<>();
        if (redisTemplate!=null){

            Object result =  redisTemplate.opsForValue().get(getTokenKey(token));
            if (result==null){
                throw new NotLoginException();
            }
            Map<String,Object> map = (Map)result;

            if (map.containsKey(ID_KEY)){
                data.put(ID_KEY, map.get(ID_KEY));
            }
            if (map.containsKey(LOGIN_TYPE_KEY)){
                data.put(LOGIN_TYPE_KEY, map.get(LOGIN_TYPE_KEY));
            }

        }else if (ApiAuthciProperty.TokenType.jwt.equals(apiAuthciProperty.getTokenType())) {
            JWT jwt = JWT.create().parse(token)
                    .setKey(apiAuthciProperty.getSecretKey().getBytes());
            JWTValidator.of(jwt).validateDate();
            JSONObject payloads = jwt.getPayloads();

            if (payloads.containsKey(ID_KEY)){
                data.put(ID_KEY, payloads.get(ID_KEY));
            }else if (payloads.containsKey(LOGIN_TYPE_KEY)){
                data.put(LOGIN_TYPE_KEY, payloads.get(LOGIN_TYPE_KEY));
            }
        }
        if (data.isEmpty()){
            throw new NotLoginException();
        }
        dataWrapper.setData(data);
        return data;
    }

    private static String getRequestToken() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        HttpServletRequest request = attributes.getRequest();
        String token = request.getHeader(apiAuthciProperty.getHeaders().getToken());
        return token;
    }

    public static void kickout(Object loginId){

        if (redisTemplate==null) {
            throw new IllegalCallerException("use kick out must have the bean of redisTemplate");
        }
        Object token = redisTemplate.opsForValue().get(getIdKey(loginId));
        if (token==null){
            return ;
        }

        redisTemplate.delete(List.of(getTokenKey(token),
                getIdKey(loginId)));

    }

    private static String getTokenKey(Object token) {
        return TOKEN_DATA_REDIS_KEY + token;
    }

    public static void logout(){
        kickout(getLoginId());
        dataWrapper.setData(null);
    }

    public static List<String> getAllApiPerms() {

        List<String> perms = new ArrayList<>();

        if (handlerMapping==null) {
            return perms;
        }

        handlerMapping.getHandlerMethods()
                .values().forEach(handler -> {
                    perms.add(MUtils.getHandlerMethodMethod(handler)+":"
                            +MUtils.concatHandlerMethodUri(handler));
                });

        return perms;

    }

    @Data
    public static class DataWrapper {
        Map data;

    }




}
