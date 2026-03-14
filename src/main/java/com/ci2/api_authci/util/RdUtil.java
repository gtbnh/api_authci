package com.ci2.api_authci.util;

import lombok.Data;
import org.redisson.api.RLock;
import org.redisson.api.RedissonClient;

import java.util.concurrent.TimeUnit;

/**
 * Redis 分布式锁工具类
 * Redis Distributed Lock Utility Class
 * 
 * 该类用于获取和管理分布式锁，基于 Redisson 实现
 * This class is used to obtain and manage distributed locks, implemented based on Redisson
 */
@Data
public class RdUtil {

    // Redisson 客户端
    // Redisson client
    private RedissonClient redissonClient;
    
    // 获取锁的等待时间（秒）
    // Wait time for obtaining lock (seconds)
    private long waitTime = 5;
    
    // 锁的租期时间（秒）
    // Lease time for lock (seconds)
    private long leaseTime = 1;
    
    // 时间单位
    // Time unit
    private TimeUnit timeUnit = TimeUnit.SECONDS;

    /**
     * 构造函数
     * Constructor
     * 
     * @param redissonClient Redisson 客户端
     * @param redissonClient Redisson client
     */
    public RdUtil(RedissonClient redissonClient) {
        this.redissonClient = redissonClient;
    }

    /**
     * 获取分布式锁
     * Get distributed lock
     * 
     * @param lockKey 锁的键
     * @param lockKey lock key
     * @param waitTime 等待时间
     * @param waitTime wait time
     * @param leaseTime 租期时间
     * @param leaseTime lease time
     * @param timeUnit 时间单位
     * @param timeUnit time unit
     * @return 锁对象
     * @return lock object
     */
    public RLock lock(String lockKey, long waitTime, long leaseTime, TimeUnit timeUnit) {
        // 获取锁对象
        // Get lock object
        RLock lock = redissonClient.getLock(lockKey);
        try {
            // 尝试获取锁
            // Try to obtain lock
            lock.tryLock(waitTime, leaseTime, timeUnit);
            return lock;
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 获取分布式锁（使用默认参数）
     * Get distributed lock (using default parameters)
     * 
     * @param lockKey 锁的键
     * @param lockKey lock key
     * @return 锁对象
     * @return lock object
     */
    public RLock lock(String lockKey) {
        return lock(lockKey, waitTime, leaseTime, timeUnit);
    }

}
