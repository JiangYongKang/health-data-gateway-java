package com.github.highcumontoa.healthdatagatewayjava.service;

import com.github.highcumontoa.healthdatagatewayjava.domain.AccessRequest;
import com.github.highcumontoa.healthdatagatewayjava.domain.Authorization;
import com.github.highcumontoa.healthdatagatewayjava.domain.Decision;
import com.github.highcumontoa.healthdatagatewayjava.domain.Delegation;
import com.github.highcumontoa.healthdatagatewayjava.domain.DelegationRequest;
import com.github.highcumontoa.healthdatagatewayjava.domain.DenyReason;
import com.github.highcumontoa.healthdatagatewayjava.store.AuthorizationStore;
import com.github.highcumontoa.healthdatagatewayjava.store.DelegationStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * 授权转授（委托）服务：
 * 1. 转授创建：校验上游授权可覆盖、范围/目的/有效期不超过上游、深度与环路限制，幂等落库；
 * 2. 转授访问：沿转授链路逐级校验到原始授权，任何一级失效即拒绝，
 *    且原始授权失效与转授权限失效给出可区分的拒绝原因；
 * 3. 级联收敛：原始授权撤回/过期后，链路上所有转授同步不可用。
 *
 * <p>同一原始授权链路的创建/访问/撤回通过 {@link ChainLock} 串行化，
 * 保证并发交错时对外结论与最新状态一致。
 */
@Service
public class DelegationService {

    private static final Logger log = LoggerFactory.getLogger(DelegationService.class);

    /** 转授链路最大深度：原始授权为 0，直接转授为 1。 */
    public static final int MAX_DELEGATION_DEPTH = 3;

    private final AuthorizationStore authorizationStore;
    private final DelegationStore delegationStore;
    private final ChainLock chainLock;
    private final AuditService auditService;

    public DelegationService(AuthorizationStore authorizationStore,
                             DelegationStore delegationStore,
                             ChainLock chainLock,
                             AuditService auditService) {
        this.authorizationStore = authorizationStore;
        this.delegationStore = delegationStore;
        this.chainLock = chainLock;
        this.auditService = auditService;
    }

    /**
     * 处理一笔转授申请。重复提交相同 delegationId 时回放已存在的关系，不重复落库、不重复审计。
     *
     * @return 生效的转授关系 + 判定结论（申请被拒绝时 delegation 为 null，decision 带可区分原因）
     */
    public DelegationResult createDelegation(DelegationRequest request) {
        List<String> basis = new ArrayList<>();
        basis.add("delegation-request=" + request.delegationId()
                + " delegator=" + request.delegatorId()
                + " delegatee=" + request.delegateeId()
                + " patient=" + request.patientId()
                + " purpose=" + request.purpose()
                + " scopes=" + request.scopes()
                + " validity=[" + request.validFrom() + "," + request.validUntil() + ")");

        // 1. 幂等：相同 delegationId 回放首次结论，不产生第二条关系
        Optional<Delegation> existing = delegationStore.findById(request.delegationId());
        if (existing.isPresent()) {
            Delegation first = existing.get();
            basis.add("idempotent-replay: delegationId=" + request.delegationId()
                    + " 已存在转授关系，不再重复创建");
            basis.add(traceNote(first));
            log.info("[delegation] replay delegationId={}", request.delegationId());
            return new DelegationResult(first, Decision.allow(basis));
        }

        // 2. 基础合法性：不能转授给自己
        if (request.delegatorId().equals(request.delegateeId())) {
            basis.add("check=party result=FAIL 转授方与被转授方不得为同一机构");
            return new DelegationResult(null,
                    Decision.deny(DenyReason.DELEGATION_CYCLE, basis));
        }

        // 3. 收集转授方可能的上游来源（自有原始授权 + 其作为被转授方的转授关系）。
        //    上游可能来自多条原始授权链路，需要先在无锁快照中确定候选，再按链路加锁校验，
        //    避免“锁内再取数导致的环锁”，同时多链路之间不会并发修改彼此。
        Instant now = Instant.now();
        List<UpstreamGrant> candidates = collectUpstreamGrants(request, now);
        if (candidates.isEmpty()) {
            basis.add("check=source-coverage result=FAIL 转授方不持有针对该患者的任何有效授权/转授");
            basis.add("conclude=DELEGATION_SOURCE_NOT_COVERED 无可用上游授权");
            return new DelegationResult(null,
                    Decision.deny(DenyReason.DELEGATION_SOURCE_NOT_COVERED, basis));
        }

        // 按根链路分组（每条链路独立加锁），优先使用原始授权（深度 0），其次较浅的转授
        candidates.sort(Comparator.comparingInt(UpstreamGrant::depth));
        for (UpstreamGrant grant : candidates) {
            DelegationResult result = chainLock.withLock(grant.rootAuthorizationId(),
                    () -> tryCreateOnGrant(request, grant, now, basis));
            if (result != null) {
                return result;
            }
        }

        // 所有上游均无法覆盖本次转授：从候选明细归纳可区分原因
        basis.add("check=source-coverage result=FAIL 所有上游授权均不能覆盖本次转授请求");
        DenyReason reason = summarizeUncovered(candidates, request, now, basis);
        return new DelegationResult(null, Decision.deny(reason, basis));
    }

    /** 在某一条已加锁的上游链路上尝试创建转授；上游不适用时返回 null 以尝试下一候选。 */
    private DelegationResult tryCreateOnGrant(DelegationRequest request, UpstreamGrant grant,
                                              Instant now, List<String> sharedBasis) {
        List<String> basis = new ArrayList<>(sharedBasis);

        // 锁内重新读取上游最新状态（可能在选候选后被撤回/过期）
        Optional<? extends UpstreamGrant> fresh = grant.refresh(authorizationStore, delegationStore);
        if (fresh.isEmpty() || !fresh.get().effectiveAt(now)) {
            basis.add("upstream=" + grant.describe() + " 在加锁后已失效，跳过该链路");
            return null;
        }
        UpstreamGrant up = fresh.get();

        // 深度上限
        if (up.depth() >= MAX_DELEGATION_DEPTH) {
            basis.add("check=depth result=FAIL 上游深度=" + up.depth()
                    + "，再转授将超过上限 " + MAX_DELEGATION_DEPTH);
            basis.add("conclude=DELEGATION_TOO_DEEP 转授链路深度超过上限");
            return new DelegationResult(null,
                    Decision.deny(DenyReason.DELEGATION_TOO_DEEP, basis));
        }

        // 范围只能更窄或相同
        if (!up.scopes().containsAll(request.scopes())) {
            basis.add("check=scope result=FAIL 请求范围 " + request.scopes()
                    + " 超出上游 " + up.scopes() + "（" + up.describe() + "）");
            basis.add("conclude=DELEGATION_SCOPE_EXCEEDED 转授范围超过上游授权");
            return new DelegationResult(null,
                    Decision.deny(DenyReason.DELEGATION_SCOPE_EXCEEDED, basis));
        }

        // 目的不能超出
        if (!up.purposes().contains(request.purpose())) {
            basis.add("check=purpose result=FAIL 请求目的 " + request.purpose()
                    + " 超出上游 " + up.purposes() + "（" + up.describe() + "）");
            basis.add("conclude=DELEGATION_PURPOSE_EXCEEDED 转授目的超过上游授权");
            return new DelegationResult(null,
                    Decision.deny(DenyReason.DELEGATION_PURPOSE_EXCEEDED, basis));
        }

        // 有效期：不得早于上游生效、不得晚于上游失效（不超过原始授权剩余时间）
        if (request.validFrom().isBefore(up.validFrom())
                || request.validUntil().isAfter(up.validUntil())
                || !request.validUntil().isAfter(request.validFrom())) {
            basis.add("check=duration result=FAIL 请求有效期 [" + request.validFrom()
                    + "," + request.validUntil() + ") 超出上游 ["
                    + up.validFrom() + "," + up.validUntil() + ")（" + up.describe() + "）");
            basis.add("conclude=DELEGATION_DURATION_EXCEEDED 转授有效期超过上游剩余有效期");
            return new DelegationResult(null,
                    Decision.deny(DenyReason.DELEGATION_DURATION_EXCEEDED, basis));
        }

        // 环路检测：被转授方不得已经出现在该链路中（含原始授权持有人与各级转授方/被转授方）
        Set<String> chainParties = collectChainParties(up);
        if (chainParties.contains(request.delegateeId())) {
            basis.add("check=cycle result=FAIL 被转授方 " + request.delegateeId()
                    + " 已存在于链路 " + chainParties + "，将构成环");
            basis.add("conclude=DELEGATION_CYCLE 委托绕回构成环路");
            return new DelegationResult(null,
                    Decision.deny(DenyReason.DELEGATION_CYCLE, basis));
        }

        Delegation created = new Delegation(
                request.delegationId(),
                request.delegatorId(),
                request.delegateeId(),
                request.patientId(),
                Set.of(request.purpose()),
                Set.copyOf(request.scopes()),
                request.validFrom(),
                request.validUntil(),
                up.parentDelegationIdForNewLink(),
                up.rootAuthorizationId(),
                up.depth() + 1,
                false);
        DelegationStore.SaveOutcome outcome = delegationStore.saveIfAbsent(created);
        if (outcome.newlyCreated()) {
            basis.add("check=depth result=PASS 新链路深度=" + created.depth()
                    + " ≤ " + MAX_DELEGATION_DEPTH);
            basis.add("check=scope result=PASS " + request.scopes() + " ⊆ " + up.scopes());
            basis.add("check=purpose result=PASS " + request.purpose() + " ∈ " + up.purposes());
            basis.add("check=duration result=PASS [" + request.validFrom() + ","
                    + request.validUntil() + ") ⊆ [" + up.validFrom() + "," + up.validUntil() + ")");
            basis.add(traceNote(created));
            Decision allowed = Decision.allow(basis);
            // 转授授权审计在链路锁内完成：审计不可用时拒绝承认该转授（宁可拒绝，绝不静默）
            try {
                auditService.recordDelegationGrant(created, allowed);
            } catch (IllegalStateException e) {
                basis.add("audit=UNAVAILABLE 审计环节不可用，拒绝创建转授: " + e.getMessage());
                log.warn("[delegation] audit unavailable, refuse delegationId={}",
                        created.delegationId());
                return new DelegationResult(null,
                        Decision.deny(DenyReason.AUDIT_UNAVAILABLE, basis));
            }
            log.info("[delegation] created delegationId={} depth={} root={}",
                    created.delegationId(), created.depth(), created.rootAuthorizationId());
            return new DelegationResult(created, allowed);
        }
        // 并发下已被其他线程创建：幂等回放（授权审计同样只有首次一条）
        basis.add("idempotent-replay: delegationId=" + request.delegationId()
                + " 已被并发创建，回放既有关系");
        basis.add(traceNote(outcome.delegation()));
        return new DelegationResult(outcome.delegation(), Decision.allow(basis));
    }

    /**
     * 基于转授关系对一次访问做链路判定。整个判定在链路锁内完成，
     * 与原始授权撤回/级联撤回互斥，保证状态一致。
     */
    public Decision evaluateDelegatedAccess(AccessRequest request) {
        Delegation leaf = delegationStore.findById(request.delegationId()).orElse(null);
        if (leaf == null) {
            List<String> basis = new ArrayList<>();
            basis.add(accessHead(request));
            basis.add("check=delegation-existence result=FAIL 转授关系 "
                    + request.delegationId() + " 不存在");
            basis.add("conclude=DELEGATION_NOT_FOUND 引用的转授关系不存在");
            return Decision.deny(DenyReason.DELEGATION_NOT_FOUND, basis);
        }
        return chainLock.withLock(leaf.rootAuthorizationId(),
                () -> evaluateDelegatedAccessLocked(request));
    }

    private Decision evaluateDelegatedAccessLocked(AccessRequest request) {
        List<String> basis = new ArrayList<>();
        basis.add(accessHead(request));
        Instant now = Instant.now();

        Delegation leaf = delegationStore.findById(request.delegationId()).orElse(null);
        if (leaf == null) {
            basis.add("check=delegation-existence result=FAIL 转授关系不存在");
            return Decision.deny(DenyReason.DELEGATION_NOT_FOUND, basis);
        }

        // 0. 访问主体必须是该转授关系的被转授方，患者也必须一致
        if (!leaf.delegateeId().equals(request.requesterId())
                || !leaf.patientId().equals(request.patientId())) {
            basis.add("check=party result=FAIL 访问方 " + request.requesterId()
                    + "/" + request.patientId() + " 与转授关系被转授方 "
                    + leaf.delegateeId() + "/" + leaf.patientId() + " 不一致");
            basis.add("conclude=DELEGATION_PARTY_MISMATCH 请求方不是该转授关系的被转授方");
            return Decision.deny(DenyReason.DELEGATION_PARTY_MISMATCH, basis);
        }

        // 1. 先校验源头原始授权（可区分：原始授权失效）
        Authorization root = authorizationStore.findById(leaf.rootAuthorizationId()).orElse(null);
        if (root == null) {
            basis.add("check=root-existence result=FAIL 原始授权 "
                    + leaf.rootAuthorizationId() + " 不存在");
            basis.add("conclude=NO_AUTHORIZATION 转授链路源头不存在原始授权");
            return Decision.deny(DenyReason.NO_AUTHORIZATION, basis);
        }
        if (root.revoked()) {
            basis.add("check=root-revoked result=FAIL 原始授权 " + root.authorizationId()
                    + " 已撤回，其下全部转授级联失效");
            basis.add("conclude=REVOKED 原始授权已撤回，转授级联收敛");
            return Decision.deny(DenyReason.REVOKED, basis);
        }
        if (now.isBefore(root.validFrom()) || !now.isBefore(root.validUntil())) {
            basis.add("check=root-validity result=FAIL 当前 " + now + " 不在原始授权有效期 ["
                    + root.validFrom() + "," + root.validUntil() + ")，转授级联失效");
            basis.add("conclude=EXPIRED 原始授权已过期，转授级联收敛");
            return Decision.deny(DenyReason.EXPIRED, basis);
        }

        // 2. 自叶子向源头逐级走链，逐级校验（可区分：转授权限自身失效）
        List<Delegation> chain = new ArrayList<>();
        Delegation current = leaf;
        while (current != null) {
            chain.add(0, current);
            if (current.parentDelegationId() == null) {
                break;
            }
            Delegation parent = delegationStore.findById(current.parentDelegationId()).orElse(null);
            if (parent == null) {
                basis.add("check=chain-integrity result=FAIL 转授 " + current.delegationId()
                        + " 的上游 " + current.parentDelegationId() + " 缺失，链路断裂");
                basis.add("conclude=DELEGATION_NOT_FOUND 转授链路不完整");
                return Decision.deny(DenyReason.DELEGATION_NOT_FOUND, basis);
            }
            current = parent;
        }

        for (Delegation d : chain) {
            String tag = "delegation=" + d.delegationId() + "(depth=" + d.depth() + ")";
            if (d.revoked()) {
                basis.add("check=delegation-revoked result=FAIL " + tag + " 已被撤回");
                basis.add("conclude=DELEGATION_REVOKED 转授权限已撤回");
                return Decision.deny(DenyReason.DELEGATION_REVOKED, basis);
            }
            if (now.isBefore(d.validFrom()) || !now.isBefore(d.validUntil())) {
                basis.add("check=delegation-validity result=FAIL " + tag + " 当前 " + now
                        + " 不在有效期 [" + d.validFrom() + "," + d.validUntil() + ")");
                basis.add("conclude=DELEGATION_EXPIRED 转授权限已过期");
                return Decision.deny(DenyReason.DELEGATION_EXPIRED, basis);
            }
            if (!d.purposes().contains(request.purpose())) {
                basis.add("check=delegation-purpose result=FAIL " + tag + " 目的 "
                        + request.purpose() + " 未覆盖 " + d.purposes());
                basis.add("conclude=PURPOSE_NOT_COVERED 转授链路不覆盖该目的");
                return Decision.deny(DenyReason.PURPOSE_NOT_COVERED, basis);
            }
            if (!d.scopes().containsAll(request.scopes())) {
                basis.add("check=delegation-scope result=FAIL " + tag + " 范围 "
                        + request.scopes() + " 超出 " + d.scopes());
                basis.add("conclude=SCOPE_NOT_COVERED 转授链路不覆盖该范围");
                return Decision.deny(DenyReason.SCOPE_NOT_COVERED, basis);
            }
        }

        // 3. 全链有效：输出链路追溯依据
        basis.add("check=root result=PASS 原始授权 " + root.authorizationId()
                + " 有效，有效期 [" + root.validFrom() + "," + root.validUntil() + ")");
        for (Delegation d : chain) {
            basis.add("check=chain result=PASS " + d.delegatorId() + " -> "
                    + d.delegateeId() + " " + d.delegationId() + " depth=" + d.depth()
                    + " purposes=" + d.purposes() + " scopes=" + d.scopes());
        }
        basis.add("chain-trace: " + chainTrace(leaf, root.authorizationId()));
        basis.add("root-authorization=" + root.authorizationId()
                + " leaf-delegation=" + leaf.delegationId());
        return Decision.allow(basis);
    }

    /**
     * 撤回原始授权并级联撤回其下全部转授。在链路锁内原子完成，
     * 与基于该链路的访问互斥。
     *
     * @return 被级联撤回的转授关系数量
     */
    public int revokeRootAndCascade(String rootAuthorizationId) {
        return chainLock.withLock(rootAuthorizationId, () -> {
            boolean rootChanged = authorizationStore.revoke(rootAuthorizationId);
            int cascaded = 0;
            for (Delegation d : delegationStore.findByRootAuthorization(rootAuthorizationId)) {
                if (delegationStore.revoke(d.delegationId())) {
                    cascaded++;
                }
            }
            log.info("[delegation] root={} revoked(rootChanged={}) cascaded={}",
                    rootAuthorizationId, rootChanged, cascaded);
            return cascaded;
        });
    }

    /** 撤回单条转授关系（不影响上游与同级）。返回撤回是否生效。 */
    public boolean revokeDelegation(String delegationId) {
        Delegation d = delegationStore.findById(delegationId).orElse(null);
        if (d == null) {
            return false;
        }
        return chainLock.withLock(d.rootAuthorizationId(),
                () -> delegationStore.revoke(delegationId));
    }

    /** 查询转授关系的根原始授权标识（供网关在访问前定位链路锁）。 */
    public Optional<String> rootAuthorizationOf(String delegationId) {
        return delegationStore.findById(delegationId).map(Delegation::rootAuthorizationId);
    }

    /** 查询单条转授关系（供网关解析审计溯源信息）。 */
    public Optional<Delegation> findDelegation(String delegationId) {
        return delegationStore.findById(delegationId);
    }

    /** 在链路锁内执行操作（供网关把“复核+取数”与撤回互斥）。 */
    public <T> T withChainLock(String rootAuthorizationId, java.util.function.Supplier<T> action) {
        return chainLock.withLock(rootAuthorizationId, action);
    }

    // ============================ 辅助方法 ============================

    private String accessHead(AccessRequest request) {
        return "delegated-request=" + request.requestId()
                + " requester=" + request.requesterId()
                + " patient=" + request.patientId()
                + " purpose=" + request.purpose()
                + " scopes=" + request.scopes()
                + " viaDelegation=" + request.delegationId();
    }

    private List<UpstreamGrant> collectUpstreamGrants(DelegationRequest request, Instant now) {
        List<UpstreamGrant> grants = new ArrayList<>();
        // 自有原始授权
        for (Authorization auth :
                authorizationStore.findByRequesterAndPatient(request.delegatorId(), request.patientId())) {
            grants.add(new RootGrant(auth));
        }
        // 作为被转授方持有的转授
        for (Delegation d :
                delegationStore.findByDelegateeAndPatient(request.delegatorId(), request.patientId())) {
            grants.add(new DelegationGrant(d));
        }
        return grants;
    }

    /** 收集链路上已出现的全部机构（用于环路检测）。 */
    private Set<String> collectChainParties(UpstreamGrant grant) {
        Set<String> parties = new LinkedHashSet<>();
        if (grant instanceof RootGrant r) {
            parties.add(r.authorization().requesterId());
        } else if (grant instanceof DelegationGrant dg) {
            Delegation cur = dg.delegation();
            // 从当前转授沿链向上收集
            while (cur != null) {
                parties.add(cur.delegateeId());
                parties.add(cur.delegatorId());
                if (cur.parentDelegationId() == null) {
                    break;
                }
                cur = delegationStore.findById(cur.parentDelegationId()).orElse(null);
            }
            Authorization root = authorizationStore.findById(grant.rootAuthorizationId()).orElse(null);
            if (root != null) {
                parties.add(root.requesterId());
            }
        }
        return parties;
    }

    private String chainTrace(Delegation leaf, String rootAuthId) {
        List<String> path = new ArrayList<>();
        Delegation cur = leaf;
        while (cur != null) {
            path.add(0, cur.delegatorId() + "->[" + cur.delegationId() + "]->" + cur.delegateeId());
            if (cur.parentDelegationId() == null) {
                break;
            }
            cur = delegationStore.findById(cur.parentDelegationId()).orElse(null);
        }
        return "root=" + rootAuthId + " | " + String.join(" , ", path);
    }

    private String traceNote(Delegation d) {
        return "chain-trace: root=" + d.rootAuthorizationId() + " depth=" + d.depth()
                + " parent=" + d.parentDelegationId() + " " + chainTrace(d, d.rootAuthorizationId());
    }

    /** 全部上游都不覆盖时，归纳出最具体的可区分原因。 */
    private DenyReason summarizeUncovered(List<UpstreamGrant> grants, DelegationRequest request,
                                          Instant now, List<String> basis) {
        boolean scopeMiss = false, purposeMiss = false, durationMiss = false, depthMiss = false;
        boolean noneEffective = true;
        for (UpstreamGrant g : grants) {
            Optional<? extends UpstreamGrant> f = g.refresh(authorizationStore, delegationStore);
            if (f.isEmpty() || !f.get().effectiveAt(now)) {
                basis.add("upstream-invalid: " + g.describe());
                continue;
            }
            noneEffective = false;
            UpstreamGrant u = f.get();
            if (u.depth() >= MAX_DELEGATION_DEPTH) {
                depthMiss = true;
            }
            if (!u.scopes().containsAll(request.scopes())) {
                scopeMiss = true;
            }
            if (!u.purposes().contains(request.purpose())) {
                purposeMiss = true;
            }
            if (request.validFrom().isBefore(u.validFrom())
                    || request.validUntil().isAfter(u.validUntil())) {
                durationMiss = true;
            }
        }
        if (noneEffective) {
            basis.add("conclude=DELEGATION_SOURCE_NOT_COVERED 上游授权均已失效");
            return DenyReason.DELEGATION_SOURCE_NOT_COVERED;
        }
        if (depthMiss) {
            basis.add("conclude=DELEGATION_TOO_DEEP 已达转授深度上限");
            return DenyReason.DELEGATION_TOO_DEEP;
        }
        if (scopeMiss) {
            basis.add("conclude=DELEGATION_SCOPE_EXCEEDED 转授范围超过上游");
            return DenyReason.DELEGATION_SCOPE_EXCEEDED;
        }
        if (purposeMiss) {
            basis.add("conclude=DELEGATION_PURPOSE_EXCEEDED 转授目的超过上游");
            return DenyReason.DELEGATION_PURPOSE_EXCEEDED;
        }
        if (durationMiss) {
            basis.add("conclude=DELEGATION_DURATION_EXCEEDED 转授有效期超过上游剩余时间");
            return DenyReason.DELEGATION_DURATION_EXCEEDED;
        }
        basis.add("conclude=DELEGATION_SOURCE_NOT_COVERED 无可覆盖的上游授权");
        return DenyReason.DELEGATION_SOURCE_NOT_COVERED;
    }

    /** 转授申请结论：生效的关系 + 判定结论（拒绝时 delegation 为 null）。 */
    public record DelegationResult(Delegation delegation, Decision decision) {
    }

    // ============================ 上游授权抽象 ============================

    /** 转授的上游来源：可能是原始授权，也可能是另一条转授关系。 */
    private interface UpstreamGrant {
        String rootAuthorizationId();

        Set<String> purposes();

        Set<String> scopes();

        Instant validFrom();

        Instant validUntil();

        int depth();

        boolean effectiveAt(Instant now);

        String describe();

        /** 锁内重新读取最新状态；来源已被删除时 empty。 */
        Optional<? extends UpstreamGrant> refresh(AuthorizationStore authStore,
                                                  DelegationStore delegationStore);

        /** 以该上游为来源新建转授时，新关系的 parentDelegationId。 */
        String parentDelegationIdForNewLink();
    }

    private record RootGrant(Authorization authorization) implements UpstreamGrant {
        @Override
        public String rootAuthorizationId() {
            return authorization.authorizationId();
        }

        @Override
        public Set<String> purposes() {
            return authorization.purposes();
        }

        @Override
        public Set<String> scopes() {
            return authorization.scopes();
        }

        @Override
        public Instant validFrom() {
            return authorization.validFrom();
        }

        @Override
        public Instant validUntil() {
            return authorization.validUntil();
        }

        @Override
        public int depth() {
            return 0;
        }

        @Override
        public boolean effectiveAt(Instant now) {
            return !authorization.revoked()
                    && !now.isBefore(authorization.validFrom())
                    && now.isBefore(authorization.validUntil());
        }

        @Override
        public String describe() {
            return "authorization=" + authorization.authorizationId();
        }

        @Override
        public Optional<UpstreamGrant> refresh(AuthorizationStore authStore,
                                               DelegationStore delegationStore) {
            return authStore.findById(authorization.authorizationId()).map(RootGrant::new);
        }

        @Override
        public String parentDelegationIdForNewLink() {
            return null;
        }
    }

    private record DelegationGrant(Delegation delegation) implements UpstreamGrant {
        @Override
        public String rootAuthorizationId() {
            return delegation.rootAuthorizationId();
        }

        @Override
        public Set<String> purposes() {
            return delegation.purposes();
        }

        @Override
        public Set<String> scopes() {
            return delegation.scopes();
        }

        @Override
        public Instant validFrom() {
            return delegation.validFrom();
        }

        @Override
        public Instant validUntil() {
            return delegation.validUntil();
        }

        @Override
        public int depth() {
            return delegation.depth();
        }

        @Override
        public boolean effectiveAt(Instant now) {
            return !delegation.revoked()
                    && !now.isBefore(delegation.validFrom())
                    && now.isBefore(delegation.validUntil());
        }

        @Override
        public String describe() {
            return "delegation=" + delegation.delegationId();
        }

        @Override
        public Optional<UpstreamGrant> refresh(AuthorizationStore authStore,
                                               DelegationStore delegationStore) {
            return delegationStore.findById(delegation.delegationId()).map(DelegationGrant::new);
        }

        @Override
        public String parentDelegationIdForNewLink() {
            return delegation.delegationId();
        }
    }
}
