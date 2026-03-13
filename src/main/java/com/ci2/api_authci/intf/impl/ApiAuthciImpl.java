package com.ci2.api_authci.intf.impl;

import com.ci2.api_authci.intf.ApiAuthciIntf;

import java.util.List;

/**
 * API 鉴权接口默认实现
 * API Authentication Interface Default Implementation
 * 
 * 这是一个默认实现，返回空权限列表
 * This is a default implementation that returns empty permission list
 * 
 * 实际使用时，需要根据业务需求实现此接口，返回用户的实际权限列表
 * In actual use, you need to implement this interface according to business needs to return user's actual permission list
 */
public class ApiAuthciImpl implements ApiAuthciIntf {

    /**
     * 获取用户权限列表
     * Get user permission list
     * 
     * @param loginId 登录id 可能为 null
     * @param loginId login id, may be null
     * @param loginType 登录类型
     * @param loginType login type
     * @return 空权限列表
     * @return empty permission list
     */
    @Override
    public List<String> getPermissions(Object loginId, String loginType) {
        return List.of();
    }
}

