package com.ci2.api_authci.util;

import lombok.Data;
import org.redisson.api.RLock;
import org.redisson.api.RedissonClient;

import java.util.concurrent.TimeUnit;

@Data
public class RdUtil {

    private RedissonClient redissonClient;
    private long waitTime=5;
    private long leaseTime=1;
    private TimeUnit timeUnit=TimeUnit.SECONDS;

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
        return lock(lockKey, waitTime, leaseTime, timeUnit);
    }






}
