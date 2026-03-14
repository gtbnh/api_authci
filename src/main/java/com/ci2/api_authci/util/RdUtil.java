package com.ci2.api_authci.util;

import org.redisson.api.RLock;
import org.redisson.api.RedissonClient;

import java.util.concurrent.TimeUnit;

public class RdUtil {

    private RedissonClient redissonClient;

    public RdUtil(RedissonClient redissonClient) {
        this.redissonClient = redissonClient;
    }

    public RLock lock(String lockKey, long waitTime, long leaseTime,TimeUnit timeUnit) {

        RLock lock = redissonClient.getLock(lockKey);
        try {
            lock.tryLock(waitTime,leaseTime,timeUnit);
            return lock;

        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

    }

    public RLock lock(String lockKey) {
        return lock(lockKey, 3, -1, TimeUnit.SECONDS);
    }






}
