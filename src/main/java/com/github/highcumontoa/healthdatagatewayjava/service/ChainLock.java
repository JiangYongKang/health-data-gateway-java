package com.github.highcumontoa.healthdatagatewayjava.service;

import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

/**
 * 转授链路锁：以链路源头的原始授权标识为键，对同一链路的
 * “转授访问判定 / 原始授权撤回 / 级联撤回 / 转授创建”进行串行化，
 * 保证并发访问与撤回交错时，对外结论始终与最新状态一致
 * （不会出现拿着已失效转授权限读到数据的情况）。
 *
 * <p>不同原始授权之间互不阻塞。
 */
@Component
public class ChainLock {

    private final ConcurrentHashMap<String, ReentrantLock> locks = new ConcurrentHashMap<>();

    private ReentrantLock lockFor(String rootAuthorizationId) {
        return locks.computeIfAbsent(rootAuthorizationId, k -> new ReentrantLock());
    }

    /** 在指定链路锁内执行有返回值的操作。 */
    public <T> T withLock(String rootAuthorizationId, Supplier<T> action) {
        ReentrantLock lock = lockFor(rootAuthorizationId);
        lock.lock();
        try {
            return action.get();
        } finally {
            lock.unlock();
        }
    }

    /** 在指定链路锁内执行无返回值的操作。 */
    public void withLock(String rootAuthorizationId, Runnable action) {
        withLock(rootAuthorizationId, () -> {
            action.run();
            return null;
        });
    }
}
