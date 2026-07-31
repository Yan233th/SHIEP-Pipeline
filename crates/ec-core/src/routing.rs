use crate::error::{EcError, EcResult};
use crate::route_table::{PortRange, RouteRule, RouteTable};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex, OnceLock};

static ROUTER: OnceLock<Mutex<RouteMode>> = OnceLock::new();
const ROUTER_NOT_INITIALIZED: &str = "route matcher is not initialized";

#[derive(Debug, Clone)]
pub struct RouteInstallSummary {
    pub rule_count: usize,
    pub dns_server_count: usize,
    pub dns_record_count: usize,
    pub dns_scope_count: usize,
}

#[derive(Debug, Clone)]
pub enum RoutePlan {
    Remote {
        dial: String,
        rc_id: i32,
        rc_name: String,
        source: RouteSource,
        dns_lookup: Option<crate::dns_resolver::ResolveSource>,
    },
    Fallback {
        target: String,
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteSource {
    RouteTableUnavailable,
    RuleIp,
    DnsMap,
    DnsDataIpRule,
    DnsServer,
    CnameDnsMap,
    CnameDnsServer,
    DnsServerIpRule,
}

impl RouteSource {
    pub fn label(self) -> &'static str {
        match self {
            RouteSource::RouteTableUnavailable => "route-table-unavailable",
            RouteSource::RuleIp => "rule-ip",
            RouteSource::DnsMap => "dns-map",
            RouteSource::DnsDataIpRule => "dns-data-ip-rule",
            RouteSource::DnsServer => "dns-server",
            RouteSource::CnameDnsMap => "cname-dns-map",
            RouteSource::CnameDnsServer => "cname-dns-server",
            RouteSource::DnsServerIpRule => "dns-server-ip-rule",
        }
    }
}

pub fn install_route_table(table: RouteTable) -> EcResult<RouteInstallSummary> {
    let matcher = RouteMatcher::from_table(table)?;
    let summary = RouteInstallSummary {
        rule_count: matcher.rules.len(),
        dns_server_count: matcher.dns_servers.len(),
        dns_record_count: matcher.dns_records,
        dns_scope_count: matcher.trusted_dns_scopes.len(),
    };
    let holder = ROUTER.get_or_init(|| Mutex::new(RouteMode::Unavailable));
    let mut guard = holder
        .lock()
        .map_err(|_| EcError::Runtime("route matcher mutex poisoned".to_string()))?;
    crate::dns_resolver::clear_cache();
    *guard = RouteMode::Matcher(Arc::new(matcher));
    Ok(summary)
}

pub fn install_tunnel_fallback() -> EcResult<()> {
    let holder = ROUTER.get_or_init(|| Mutex::new(RouteMode::Unavailable));
    let mut guard = holder
        .lock()
        .map_err(|_| EcError::Runtime("route matcher mutex poisoned".to_string()))?;
    crate::dns_resolver::clear_cache();
    *guard = RouteMode::TunnelFallback;
    Ok(())
}

pub fn plan_target(host: &str, port: u16) -> EcResult<RoutePlan> {
    let holder = ROUTER
        .get()
        .ok_or_else(|| EcError::Runtime(ROUTER_NOT_INITIALIZED.to_string()))?;
    let mode = holder
        .lock()
        .map_err(|_| EcError::Runtime("route matcher mutex poisoned".to_string()))?;
    plan_from_mode(&mode, host, port)
}

fn plan_from_mode(mode: &RouteMode, host: &str, port: u16) -> EcResult<RoutePlan> {
    match mode {
        RouteMode::Matcher(matcher) => Ok(matcher.plan(host, port)),
        RouteMode::TunnelFallback => match parse_target(host) {
            TargetKind::Ipv6(ip) => Ok(plan_ipv6_fallback(ip, port)),
            _ => Ok(RoutePlan::Remote {
                dial: format!("{host}:{port}"),
                rc_id: 0,
                rc_name: "route-table-unavailable".to_string(),
                source: RouteSource::RouteTableUnavailable,
                dns_lookup: None,
            }),
        },
        RouteMode::Unavailable => Err(EcError::Runtime(ROUTER_NOT_INITIALIZED.to_string())),
    }
}

#[derive(Debug, Clone)]
enum RouteMode {
    Unavailable,
    Matcher(Arc<RouteMatcher>),
    TunnelFallback,
}

#[derive(Debug, Clone)]
struct RouteMatcher {
    rules: Vec<CompiledRule>,
    rule_index: RuleIndex,
    dns_map: HashMap<i32, HashMap<String, Vec<Ipv4Addr>>>,
    dns_exact: HashMap<String, Vec<Ipv4Addr>>,
    dns_servers: Vec<SocketAddr>,
    dns_records: usize,
    trusted_dns_scopes: HashSet<String>,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    rc_id: i32,
    rc_name: String,
    svc: String,
    matcher: HostMatcher,
    port: PortRange,
}

#[derive(Debug, Clone, Default)]
struct RuleIndex {
    domain: HashMap<String, Vec<usize>>,
    ipv4: HashMap<Ipv4Addr, Vec<usize>>,
    range_buckets: Vec<Vec<usize>>,
}

#[derive(Debug, Clone)]
enum HostMatcher {
    Domain(String),
    Ipv4(Ipv4Addr),
    Ipv4Range(u32, u32),
}

#[derive(Debug, Clone)]
enum TargetKind {
    Domain(String),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

#[derive(Debug, Default)]
struct DnsScopeTrieNode {
    children: HashMap<String, DnsScopeTrieNode>,
    terminal: bool,
    synthetic: bool,
}

impl RouteMatcher {
    fn from_table(table: RouteTable) -> EcResult<Self> {
        let RouteTable {
            rules: raw_rules,
            dns_servers,
            dns_records: raw_dns_records,
            ..
        } = table;

        let rules = compile_rules(raw_rules);
        let rule_index = RuleIndex::build(&rules);
        let trusted_dns_scopes =
            infer_trusted_dns_scopes(rules.iter().filter_map(|rule| match &rule.matcher {
                HostMatcher::Domain(domain) => Some(domain.as_str()),
                HostMatcher::Ipv4(_) | HostMatcher::Ipv4Range(_, _) => None,
            }));
        let dns_indexes = build_dns_indexes(raw_dns_records);
        let dns_servers = normalize_dns_servers(dns_servers);

        Ok(Self {
            rules,
            rule_index,
            dns_map: dns_indexes.scoped,
            dns_exact: dns_indexes.exact,
            dns_servers,
            dns_records: dns_indexes.record_count,
            trusted_dns_scopes,
        })
    }

    fn plan(&self, host: &str, port: u16) -> RoutePlan {
        let target = parse_target(host);
        if let TargetKind::Ipv6(ip) = target {
            return plan_ipv6_fallback(ip, port);
        }
        if let Some(rule) = self.rule_index.find_first_match(&self.rules, &target, port) {
            return self.plan_remote_with_rule(rule, host, port, &target);
        }

        if let TargetKind::Domain(domain) = &target
            && let Some(plan) = self.plan_dns_data_ip_rule(port, domain)
        {
            return plan;
        }

        if let TargetKind::Domain(domain) = &target
            && let Some(plan) = self.plan_dnsserver_derived_rules(host, port, domain)
        {
            return plan;
        }

        RoutePlan::Fallback {
            target: format!("{host}:{port}"),
            reason: "no whitelist rule matched".to_string(),
        }
    }

    fn plan_remote_with_rule(
        &self,
        rule: &CompiledRule,
        host: &str,
        port: u16,
        target: &TargetKind,
    ) -> RoutePlan {
        match target {
            TargetKind::Ipv4(ip) => RoutePlan::Remote {
                dial: format!("{ip}:{port}"),
                rc_id: rule.rc_id,
                rc_name: rule.rc_name.clone(),
                source: RouteSource::RuleIp,
                dns_lookup: None,
            },
            TargetKind::Ipv6(ip) => plan_ipv6_fallback(*ip, port),
            TargetKind::Domain(domain) => {
                if let Some(ipv4s) = self
                    .dns_map
                    .get(&rule.rc_id)
                    .and_then(|domains| domains.get(domain))
                    && let Some(ip) = ipv4s.first()
                {
                    return RoutePlan::Remote {
                        dial: format!("{ip}:{port}"),
                        rc_id: rule.rc_id,
                        rc_name: rule.rc_name.clone(),
                        source: RouteSource::DnsMap,
                        dns_lookup: None,
                    };
                }
                if self.dns_servers.is_empty() {
                    return RoutePlan::Fallback {
                        target: format!("{host}:{port}"),
                        reason: "hostname matched a route rule but dns.data entry is missing and DNS servers are unavailable"
                            .to_string(),
                    };
                }

                match crate::dns_resolver::resolve_first_ipv4(rule.rc_id, domain, &self.dns_servers)
                {
                    Ok(resolved) => {
                        let dns_lookup = resolved.source;
                        RoutePlan::Remote {
                            dial: format!("{}:{port}", resolved.ip),
                            rc_id: rule.rc_id,
                            rc_name: rule.rc_name.clone(),
                            source: RouteSource::DnsServer,
                            dns_lookup: Some(dns_lookup),
                        }
                    }
                    Err(err) => RoutePlan::Fallback {
                        target: format!("{host}:{port}"),
                        reason: format!(
                            "hostname matched a route rule but dns.data entry is missing and DNS lookup failed: {}",
                            crate::error::concise_error(err)
                        ),
                    },
                }
            }
        }
    }

    fn plan_dns_data_ip_rule(&self, port: u16, domain: &str) -> Option<RoutePlan> {
        let ips = self.dns_exact.get(domain)?;
        self.plan_from_resolved_ips(port, ips, RouteSource::DnsDataIpRule, None)
    }

    fn plan_dnsserver_derived_rules(
        &self,
        host: &str,
        port: u16,
        domain: &str,
    ) -> Option<RoutePlan> {
        if self.dns_servers.is_empty() || !self.is_trusted_dns_domain(domain) {
            return None;
        }
        let resolved = crate::dns_resolver::resolve_lookup(domain, &self.dns_servers).ok()?;
        if let Some(plan) =
            self.plan_from_cname_aliases(host, port, &resolved.aliases, resolved.source)
        {
            return Some(plan);
        }
        let dns_lookup = resolved.source;
        self.plan_from_resolved_ips(
            port,
            &resolved.ips,
            RouteSource::DnsServerIpRule,
            Some(dns_lookup),
        )
    }

    fn plan_from_cname_aliases(
        &self,
        host: &str,
        port: u16,
        aliases: &[String],
        dns_lookup: crate::dns_resolver::ResolveSource,
    ) -> Option<RoutePlan> {
        for alias in aliases {
            let alias = normalize_domain(alias);
            if alias.is_empty() || Ipv4Addr::from_str(&alias).is_ok() {
                continue;
            }
            let target = TargetKind::Domain(alias);
            if let Some(rule) = self.rule_index.find_first_match(&self.rules, &target, port) {
                return Some(
                    self.plan_remote_with_cname_rule(rule, host, port, &target)
                        .with_dns_lookup_if_absent(dns_lookup),
                );
            }
        }
        None
    }

    fn is_trusted_dns_domain(&self, domain: &str) -> bool {
        let mut candidate = domain;
        loop {
            if self.trusted_dns_scopes.contains(candidate) {
                return true;
            }
            let Some((_, parent)) = candidate.split_once('.') else {
                return false;
            };
            candidate = parent;
        }
    }

    fn plan_from_resolved_ips(
        &self,
        port: u16,
        ips: &[Ipv4Addr],
        source: RouteSource,
        dns_lookup: Option<crate::dns_resolver::ResolveSource>,
    ) -> Option<RoutePlan> {
        for ip in ips {
            let target = TargetKind::Ipv4(*ip);
            if let Some(rule) = self.rule_index.find_first_match(&self.rules, &target, port) {
                return Some(RoutePlan::Remote {
                    dial: format!("{ip}:{port}"),
                    rc_id: rule.rc_id,
                    rc_name: rule.rc_name.clone(),
                    source,
                    dns_lookup,
                });
            }
        }
        None
    }

    fn plan_remote_with_cname_rule(
        &self,
        rule: &CompiledRule,
        host: &str,
        port: u16,
        target: &TargetKind,
    ) -> RoutePlan {
        match self.plan_remote_with_rule(rule, host, port, target) {
            RoutePlan::Remote {
                dial,
                rc_id,
                rc_name,
                source,
                dns_lookup,
            } => RoutePlan::Remote {
                dial,
                rc_id,
                rc_name,
                source: cname_route_source(source),
                dns_lookup,
            },
            other => other,
        }
    }
}

impl RoutePlan {
    fn with_dns_lookup_if_absent(mut self, source: crate::dns_resolver::ResolveSource) -> Self {
        if let Self::Remote { dns_lookup, .. } = &mut self
            && dns_lookup.is_none()
        {
            *dns_lookup = Some(source);
        }
        self
    }
}

impl DnsScopeTrieNode {
    fn insert(&mut self, domain: &str) {
        let mut node = self;
        for label in domain.split('.').rev() {
            if label.is_empty() {
                return;
            }
            node = node.children.entry(label.to_string()).or_default();
        }
        node.terminal = true;
    }

    fn collapse(&mut self, depth: usize) {
        for child in self.children.values_mut() {
            child.collapse(depth + 1);
        }

        if depth >= 2
            && self
                .children
                .values()
                .filter(|child| child.is_leaf())
                .count()
                >= 2
        {
            self.children.clear();
            self.synthetic = true;
        }
    }

    fn collect_synthetic_leaves<'a>(
        &'a self,
        reversed_labels: &mut Vec<&'a str>,
        scopes: &mut HashSet<String>,
    ) {
        if self.synthetic && self.children.is_empty() {
            scopes.insert(
                reversed_labels
                    .iter()
                    .rev()
                    .copied()
                    .collect::<Vec<_>>()
                    .join("."),
            );
            return;
        }

        for (label, child) in &self.children {
            reversed_labels.push(label);
            child.collect_synthetic_leaves(reversed_labels, scopes);
            reversed_labels.pop();
        }
    }

    fn is_leaf(&self) -> bool {
        self.children.is_empty() && (self.terminal || self.synthetic)
    }
}

fn infer_trusted_dns_scopes<'a>(domains: impl IntoIterator<Item = &'a str>) -> HashSet<String> {
    let mut root = DnsScopeTrieNode::default();
    for domain in domains {
        root.insert(domain);
    }
    root.collapse(0);

    let mut scopes = HashSet::new();
    root.collect_synthetic_leaves(&mut Vec::new(), &mut scopes);
    scopes
}

fn cname_route_source(source: RouteSource) -> RouteSource {
    match source {
        RouteSource::DnsMap => RouteSource::CnameDnsMap,
        RouteSource::DnsServer => RouteSource::CnameDnsServer,
        other => other,
    }
}

impl RuleIndex {
    fn build(rules: &[CompiledRule]) -> Self {
        let mut index = Self {
            domain: HashMap::new(),
            ipv4: HashMap::new(),
            range_buckets: vec![Vec::new(); 256],
        };
        for (idx, rule) in rules.iter().enumerate() {
            match &rule.matcher {
                HostMatcher::Domain(domain) => {
                    index.domain.entry(domain.clone()).or_default().push(idx);
                }
                HostMatcher::Ipv4(ip) => {
                    index.ipv4.entry(*ip).or_default().push(idx);
                }
                HostMatcher::Ipv4Range(start, end) => {
                    let start_bucket = ((*start >> 24) & 0xff) as usize;
                    let end_bucket = ((*end >> 24) & 0xff) as usize;
                    for bucket in start_bucket..=end_bucket {
                        index.range_buckets[bucket].push(idx);
                    }
                }
            }
        }
        index
    }

    fn find_first_match<'a>(
        &self,
        rules: &'a [CompiledRule],
        target: &TargetKind,
        port: u16,
    ) -> Option<&'a CompiledRule> {
        match target {
            TargetKind::Domain(domain) => self
                .domain
                .get(domain)
                .and_then(|ids| {
                    ids.iter()
                        .find_map(|&idx| rule_matches(&rules[idx], port).then_some(idx))
                })
                .map(|idx| &rules[idx]),
            TargetKind::Ipv4(ip) => {
                let mut best_idx: Option<usize> = None;
                if let Some(ids) = self.ipv4.get(ip) {
                    for &idx in ids {
                        if rule_matches(&rules[idx], port) && best_idx.is_none_or(|best| idx < best)
                        {
                            best_idx = Some(idx);
                        }
                    }
                }
                let needle = u32::from(*ip);
                let bucket = ((needle >> 24) & 0xff) as usize;
                for &idx in &self.range_buckets[bucket] {
                    let rule = &rules[idx];
                    let HostMatcher::Ipv4Range(start, end) = &rule.matcher else {
                        continue;
                    };
                    if *start <= needle
                        && needle <= *end
                        && rule_matches(rule, port)
                        && best_idx.is_none_or(|best| idx < best)
                    {
                        best_idx = Some(idx);
                    }
                }
                best_idx.map(|idx| &rules[idx])
            }
            TargetKind::Ipv6(_) => None,
        }
    }
}

fn normalize_dns_servers(servers: Vec<String>) -> Vec<SocketAddr> {
    const DNS_DEFAULT_PORT: u16 = 53;

    let mut out = Vec::with_capacity(servers.len());
    let mut seen = HashSet::<SocketAddr>::with_capacity(servers.len());
    for raw in servers {
        let token = raw.trim();
        if token.is_empty() {
            continue;
        }
        let addr = if let Ok(addr) = token.parse::<SocketAddr>() {
            Some(addr)
        } else if let Ok(ip) = token.parse::<IpAddr>() {
            Some(SocketAddr::new(ip, DNS_DEFAULT_PORT))
        } else {
            None
        };
        let Some(addr) = addr else {
            continue;
        };
        if seen.insert(addr) {
            out.push(addr);
        }
    }
    out
}

fn compile_rules(raw_rules: Vec<RouteRule>) -> Vec<CompiledRule> {
    let mut rules = Vec::with_capacity(raw_rules.len());
    let mut seen_rules = HashSet::<RuleDedupKey>::with_capacity(raw_rules.len());
    for rule in raw_rules {
        if let Some(compiled) = compile_rule(rule) {
            let key = compiled.dedup_key();
            if seen_rules.insert(key) {
                rules.push(compiled);
            }
        }
    }
    rules
}

#[derive(Debug, Clone)]
struct DnsIndexes {
    scoped: HashMap<i32, HashMap<String, Vec<Ipv4Addr>>>,
    exact: HashMap<String, Vec<Ipv4Addr>>,
    record_count: usize,
}

fn build_dns_indexes(raw_dns_records: Vec<crate::route_table::DnsRecord>) -> DnsIndexes {
    let mut scoped = HashMap::<i32, HashMap<String, Vec<Ipv4Addr>>>::new();
    let mut exact = HashMap::<String, Vec<Ipv4Addr>>::new();
    let mut seen_dns = HashSet::<(i32, String, Ipv4Addr)>::with_capacity(raw_dns_records.len());
    let mut seen_exact = HashSet::<(String, Ipv4Addr)>::with_capacity(raw_dns_records.len());
    for rec in raw_dns_records {
        let host = normalize_domain(&rec.host);
        if host.is_empty() {
            continue;
        }
        let Ok(ip) = Ipv4Addr::from_str(rec.ip.trim()) else {
            continue;
        };
        if !seen_dns.insert((rec.rc_id, host.clone(), ip)) {
            continue;
        }
        scoped
            .entry(rec.rc_id)
            .or_default()
            .entry(host.clone())
            .or_default()
            .push(ip);
        if seen_exact.insert((host.clone(), ip)) {
            exact.entry(host).or_default().push(ip);
        }
    }
    DnsIndexes {
        scoped,
        exact,
        record_count: seen_dns.len(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RuleDedupKey {
    rc_id: i32,
    rc_name: String,
    svc: String,
    matcher: MatcherDedupKey,
    port_start: u16,
    port_end: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum MatcherDedupKey {
    Domain(String),
    Ipv4(Ipv4Addr),
    Ipv4Range(u32, u32),
}

impl CompiledRule {
    fn dedup_key(&self) -> RuleDedupKey {
        let matcher = match &self.matcher {
            HostMatcher::Domain(host) => MatcherDedupKey::Domain(host.clone()),
            HostMatcher::Ipv4(ip) => MatcherDedupKey::Ipv4(*ip),
            HostMatcher::Ipv4Range(a, b) => MatcherDedupKey::Ipv4Range(*a, *b),
        };
        RuleDedupKey {
            rc_id: self.rc_id,
            rc_name: self.rc_name.clone(),
            svc: self.svc.clone(),
            matcher,
            port_start: self.port.start,
            port_end: self.port.end,
        }
    }
}

fn compile_rule(rule: RouteRule) -> Option<CompiledRule> {
    let vipall = rule.svc.trim() == "vipall";
    if !vipall && !matches!(rule.proto, -1 | 0) {
        return None;
    }

    let matcher = if rule.host.contains('~') {
        let (start, end) = rule.host.split_once('~')?;
        let a = Ipv4Addr::from_str(start.trim()).ok()?;
        let b = Ipv4Addr::from_str(end.trim()).ok()?;
        let ai = u32::from(a);
        let bi = u32::from(b);
        if ai <= bi {
            HostMatcher::Ipv4Range(ai, bi)
        } else {
            HostMatcher::Ipv4Range(bi, ai)
        }
    } else if let Ok(ip) = Ipv4Addr::from_str(rule.host.trim()) {
        HostMatcher::Ipv4(ip)
    } else {
        let domain = normalize_domain(&rule.host);
        if domain.is_empty() {
            return None;
        }
        HostMatcher::Domain(domain)
    };

    Some(CompiledRule {
        rc_id: rule.rc_id,
        rc_name: rule.name,
        svc: rule.svc,
        matcher,
        port: rule.port,
    })
}

fn parse_target(host: &str) -> TargetKind {
    let host = host.trim();
    if let Ok(ip) = Ipv4Addr::from_str(host) {
        TargetKind::Ipv4(ip)
    } else if let Ok(ip) = Ipv6Addr::from_str(host) {
        TargetKind::Ipv6(ip)
    } else {
        TargetKind::Domain(normalize_domain(host))
    }
}

fn plan_ipv6_fallback(ip: Ipv6Addr, port: u16) -> RoutePlan {
    RoutePlan::Fallback {
        target: SocketAddr::new(IpAddr::V6(ip), port).to_string(),
        reason: "IPv6 targets are fallback-only".to_string(),
    }
}

fn normalize_domain(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn port_matches(range: PortRange, port: u16) -> bool {
    range.start <= port && port <= range.end
}

fn is_vipall(rule: &CompiledRule) -> bool {
    rule.svc.trim() == "vipall"
}

fn rule_matches(rule: &CompiledRule, port: u16) -> bool {
    if is_vipall(rule) {
        return true;
    }
    port_matches(rule.port, port)
}

#[cfg(test)]
mod tests {
    use super::{
        RouteMatcher, RouteMode, RoutePlan, RouteSource, infer_trusted_dns_scopes, plan_from_mode,
    };
    use crate::route_table::{DnsRecord, PortRange, RouteRule, RouteTable};

    #[test]
    fn domain_hit_uses_dns_map_ip() {
        let table = RouteTable {
            rules: vec![RouteRule {
                rc_id: 205,
                proto: 0,
                svc: "Other".to_string(),
                name: "ids".to_string(),
                host: "ids.shiep.edu.cn".to_string(),
                port: PortRange {
                    start: 1,
                    end: 65535,
                },
            }],
            dns_servers: vec![],
            dns_records: vec![DnsRecord {
                rc_id: 205,
                host: "ids.shiep.edu.cn".to_string(),
                ip: "10.166.35.11".to_string(),
            }],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        let plan = matcher.plan("ids.shiep.edu.cn", 443);
        match plan {
            RoutePlan::Remote {
                dial,
                rc_id,
                source,
                dns_lookup,
                ..
            } => {
                assert_eq!(dial, "10.166.35.11:443");
                assert_eq!(rc_id, 205);
                assert_eq!(source, RouteSource::DnsMap);
                assert_eq!(dns_lookup, None);
            }
            _ => panic!("expected remote plan"),
        }
    }

    #[test]
    fn dns_scope_trie_merges_sibling_domain_leaves() {
        let scopes =
            infer_trusted_dns_scopes(["pan.shiep.edu.cn", "ids.shiep.edu.cn", "pan.shiep.edu.cn"]);

        assert_eq!(scopes, ["shiep.edu.cn".to_string()].into());
    }

    #[test]
    fn dns_scope_trie_does_not_count_terminal_internal_nodes_as_leaves() {
        let scopes = infer_trusted_dns_scopes(["shiep.edu.cn", "ids.shiep.edu.cn"]);

        assert!(scopes.is_empty());
    }

    #[test]
    fn dns_scope_trie_recursively_merges_but_stops_before_one_label() {
        let scopes = infer_trusted_dns_scopes([
            "pan.shiep.edu.cn",
            "ids.shiep.edu.cn",
            "portal.other.edu.cn",
            "mail.other.edu.cn",
            "foo.com",
            "bar.com",
        ]);

        assert_eq!(scopes, ["edu.cn".to_string()].into());
    }

    #[test]
    fn dns_scope_trie_collapses_entire_mixed_subtree() {
        let scopes = infer_trusted_dns_scopes([
            "pan.shiep.edu.cn",
            "ids.shiep.edu.cn",
            "deep.branch.shiep.edu.cn",
        ]);

        assert_eq!(scopes, ["shiep.edu.cn".to_string()].into());
    }

    #[test]
    fn inferred_dns_scope_authorizes_itself_and_subdomains_only() {
        let matcher = RouteMatcher::from_table(RouteTable {
            rules: vec![
                domain_rule(201, "pan.shiep.edu.cn"),
                domain_rule(202, "ids.shiep.edu.cn"),
            ],
            dns_servers: vec![],
            dns_records: vec![],
        })
        .unwrap();

        assert!(matcher.is_trusted_dns_domain("shiep.edu.cn"));
        assert!(matcher.is_trusted_dns_domain("pan2.shiep.edu.cn"));
        assert!(matcher.is_trusted_dns_domain("estudent.shiep.edu.cn"));
        assert!(!matcher.is_trusted_dns_domain("github.com"));
        assert!(!matcher.is_trusted_dns_domain("api.github.com"));
        assert!(!matcher.is_trusted_dns_domain("notshiep.edu.cn"));
    }

    #[test]
    fn untrusted_domain_skips_dnsserver_derived_matching() {
        let matcher = RouteMatcher::from_table(RouteTable {
            rules: vec![
                domain_rule(201, "pan.shiep.edu.cn"),
                domain_rule(202, "ids.shiep.edu.cn"),
            ],
            dns_servers: vec!["127.0.0.1:1".to_string()],
            dns_records: vec![],
        })
        .unwrap();

        let plan = matcher.plan("github.com", 443);
        match plan {
            RoutePlan::Fallback { target, reason } => {
                assert_eq!(target, "github.com:443");
                assert_eq!(reason, "no whitelist rule matched");
            }
            _ => panic!("expected fallback plan"),
        }
    }

    #[test]
    fn tunnel_fallback_mode_routes_non_ipv6_targets_remote() {
        let plan = plan_from_mode(&RouteMode::TunnelFallback, "example.invalid", 443).unwrap();
        match plan {
            RoutePlan::Remote {
                dial,
                rc_id,
                rc_name,
                source,
                ..
            } => {
                assert_eq!(dial, "example.invalid:443");
                assert_eq!(rc_id, 0);
                assert_eq!(rc_name, "route-table-unavailable");
                assert_eq!(source, RouteSource::RouteTableUnavailable);
            }
            _ => panic!("expected remote tunnel fallback plan"),
        }
    }

    #[test]
    fn explicit_ipv6_falls_back_before_route_matching() {
        let table = RouteTable {
            rules: vec![RouteRule {
                rc_id: 400,
                proto: 0,
                svc: "Other".to_string(),
                name: "must-not-match".to_string(),
                host: "2001:db8::1".to_string(),
                port: PortRange {
                    start: 1,
                    end: 65535,
                },
            }],
            dns_servers: vec!["127.0.0.1:1".to_string()],
            dns_records: vec![],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        let plan = matcher.plan("2001:db8::1", 443);
        match plan {
            RoutePlan::Fallback { target, reason } => {
                assert_eq!(target, "[2001:db8::1]:443");
                assert_eq!(reason, "IPv6 targets are fallback-only");
            }
            _ => panic!("expected IPv6 fallback plan"),
        }
    }

    #[test]
    fn tunnel_fallback_mode_keeps_ipv6_out_of_tunnel() {
        let plan = plan_from_mode(&RouteMode::TunnelFallback, "2001:db8::1", 443).unwrap();
        match plan {
            RoutePlan::Fallback { target, reason } => {
                assert_eq!(target, "[2001:db8::1]:443");
                assert_eq!(reason, "IPv6 targets are fallback-only");
            }
            _ => panic!("expected IPv6 fallback plan"),
        }
    }

    #[test]
    fn dns_data_exact_host_without_ip_rule_falls_back() {
        let table = RouteTable {
            rules: vec![],
            dns_servers: vec![],
            dns_records: vec![DnsRecord {
                rc_id: 244,
                host: "ecard.shiep.edu.cn".to_string(),
                ip: "10.168.103.76".to_string(),
            }],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        let plan = matcher.plan("ecard.shiep.edu.cn", 80);
        match plan {
            RoutePlan::Fallback { reason, .. } => {
                assert_eq!(reason, "no whitelist rule matched");
            }
            _ => panic!("expected fallback plan"),
        }
    }

    #[test]
    fn dns_data_exact_host_can_route_through_ip_range_rule() {
        let table = RouteTable {
            rules: vec![RouteRule {
                rc_id: 301,
                proto: 0,
                svc: "Other".to_string(),
                name: "ip-range".to_string(),
                host: "10.166.0.1~10.166.255.254".to_string(),
                port: PortRange {
                    start: 10002,
                    end: 10002,
                },
            }],
            dns_servers: vec![],
            dns_records: vec![DnsRecord {
                rc_id: 244,
                host: "pan2.shiep.edu.cn".to_string(),
                ip: "10.166.64.9".to_string(),
            }],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        let plan = matcher.plan("pan2.shiep.edu.cn", 10002);
        match plan {
            RoutePlan::Remote {
                dial,
                rc_id,
                source,
                ..
            } => {
                assert_eq!(dial, "10.166.64.9:10002");
                assert_eq!(rc_id, 301);
                assert_eq!(source, RouteSource::DnsDataIpRule);
            }
            _ => panic!("expected remote plan"),
        }
    }

    #[test]
    fn dns_data_exact_host_never_matches_domain_rule_by_ip_text() {
        let table = RouteTable {
            rules: vec![RouteRule {
                rc_id: 302,
                proto: 0,
                svc: "Other".to_string(),
                name: "domain-text-ip".to_string(),
                host: "resolved.example".to_string(),
                port: PortRange { start: 80, end: 80 },
            }],
            dns_servers: vec![],
            dns_records: vec![DnsRecord {
                rc_id: 244,
                host: "pan2.shiep.edu.cn".to_string(),
                ip: "10.166.64.9".to_string(),
            }],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        let plan = matcher.plan("pan2.shiep.edu.cn", 80);
        match plan {
            RoutePlan::Fallback { reason, .. } => {
                assert_eq!(reason, "no whitelist rule matched");
            }
            _ => panic!("expected fallback plan"),
        }
    }

    #[test]
    fn dns_data_exact_host_skips_udp_only_ip_rule_for_tcp() {
        let table = RouteTable {
            rules: vec![RouteRule {
                rc_id: -98,
                proto: 1,
                svc: "".to_string(),
                name: "__DNS_HIDE_RC1".to_string(),
                host: "210.35.88.5".to_string(),
                port: PortRange { start: 53, end: 53 },
            }],
            dns_servers: vec![],
            dns_records: vec![DnsRecord {
                rc_id: -98,
                host: "dns-hide.example".to_string(),
                ip: "210.35.88.5".to_string(),
            }],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        let plan = matcher.plan("dns-hide.example", 53);
        match plan {
            RoutePlan::Fallback { reason, .. } => {
                assert_eq!(reason, "no whitelist rule matched");
            }
            _ => panic!("expected fallback plan"),
        }
    }

    #[test]
    fn cname_alias_can_rematch_domain_rule() {
        let table = RouteTable {
            rules: vec![RouteRule {
                rc_id: 150,
                proto: 0,
                svc: "Other".to_string(),
                name: "SUEP-WAF".to_string(),
                host: "lgwf0-46.shiep.edu.cn".to_string(),
                port: PortRange {
                    start: 1,
                    end: 65535,
                },
            }],
            dns_servers: vec![],
            dns_records: vec![DnsRecord {
                rc_id: 150,
                host: "lgwf0-46.shiep.edu.cn".to_string(),
                ip: "10.166.64.6".to_string(),
            }],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        let plan = matcher
            .plan_from_cname_aliases(
                "estudent.shiep.edu.cn",
                443,
                &["lgwf0-46.shiep.edu.cn".to_string()],
                crate::dns_resolver::ResolveSource::Server("127.0.0.1:53".parse().unwrap()),
            )
            .unwrap();
        match plan {
            RoutePlan::Remote {
                dial,
                rc_id,
                source,
                dns_lookup,
                ..
            } => {
                assert_eq!(dial, "10.166.64.6:443");
                assert_eq!(rc_id, 150);
                assert_eq!(source, RouteSource::CnameDnsMap);
                assert_eq!(
                    dns_lookup,
                    Some(crate::dns_resolver::ResolveSource::Server(
                        "127.0.0.1:53".parse().unwrap()
                    ))
                );
            }
            _ => panic!("expected remote plan"),
        }
    }

    #[test]
    fn cname_alias_rematch_never_promotes_ip_to_rule_match() {
        let table = RouteTable {
            rules: vec![RouteRule {
                rc_id: 150,
                proto: 0,
                svc: "Other".to_string(),
                name: "private-ip".to_string(),
                host: "10.166.64.6".to_string(),
                port: PortRange {
                    start: 1,
                    end: 65535,
                },
            }],
            dns_servers: vec![],
            dns_records: vec![],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        let plan = matcher.plan_from_cname_aliases(
            "estudent.shiep.edu.cn",
            443,
            &["10.166.64.6".to_string()],
            crate::dns_resolver::ResolveSource::Cache,
        );
        assert!(plan.is_none());
    }

    #[test]
    fn cname_lookup_does_not_replace_a_more_direct_dns_source() {
        let inner_server = "192.0.2.53:53".parse().unwrap();
        let plan = RoutePlan::Remote {
            dial: "10.166.64.6:443".to_string(),
            rc_id: 150,
            rc_name: "SUEP-WAF".to_string(),
            source: RouteSource::CnameDnsServer,
            dns_lookup: Some(crate::dns_resolver::ResolveSource::Server(inner_server)),
        }
        .with_dns_lookup_if_absent(crate::dns_resolver::ResolveSource::Cache);

        match plan {
            RoutePlan::Remote { dns_lookup, .. } => assert_eq!(
                dns_lookup,
                Some(crate::dns_resolver::ResolveSource::Server(inner_server))
            ),
            _ => panic!("expected remote plan"),
        }
    }

    #[test]
    fn dnsserver_a_ip_can_route_through_ip_range_rule() {
        let table = RouteTable {
            rules: vec![RouteRule {
                rc_id: 302,
                proto: 0,
                svc: "Other".to_string(),
                name: "resolved-range".to_string(),
                host: "10.50.2.1~10.50.2.254".to_string(),
                port: PortRange { start: 80, end: 80 },
            }],
            dns_servers: vec![],
            dns_records: vec![],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        let ips = vec!["10.50.2.206".parse().unwrap()];
        let plan = matcher
            .plan_from_resolved_ips(
                80,
                &ips,
                RouteSource::DnsServerIpRule,
                Some(crate::dns_resolver::ResolveSource::Cache),
            )
            .unwrap();
        match plan {
            RoutePlan::Remote {
                dial,
                rc_id,
                source,
                ..
            } => {
                assert_eq!(dial, "10.50.2.206:80");
                assert_eq!(rc_id, 302);
                assert_eq!(source, RouteSource::DnsServerIpRule);
            }
            _ => panic!("expected remote plan"),
        }
    }

    #[test]
    fn ip_range_hit_goes_remote() {
        let table = RouteTable {
            rules: vec![RouteRule {
                rc_id: 334,
                proto: 0,
                svc: "Other".to_string(),
                name: "fee".to_string(),
                host: "10.50.2.1~10.50.2.254".to_string(),
                port: PortRange { start: 80, end: 80 },
            }],
            dns_servers: vec![],
            dns_records: vec![],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        let plan = matcher.plan("10.50.2.206", 80);
        match plan {
            RoutePlan::Remote { dial, source, .. } => {
                assert_eq!(dial, "10.50.2.206:80");
                assert_eq!(source, RouteSource::RuleIp);
            }
            _ => panic!("expected remote plan"),
        }
    }

    #[test]
    fn miss_falls_back() {
        let table = RouteTable {
            rules: vec![],
            dns_servers: vec![],
            dns_records: vec![],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        let plan = matcher.plan("example.com", 443);
        match plan {
            RoutePlan::Fallback { .. } => {}
            _ => panic!("expected fallback plan"),
        }
    }

    #[test]
    fn dns_duplicates_are_deduped_and_keep_order() {
        let table = RouteTable {
            rules: vec![RouteRule {
                rc_id: 205,
                proto: 0,
                svc: "Other".to_string(),
                name: "ids".to_string(),
                host: "ids.shiep.edu.cn".to_string(),
                port: PortRange {
                    start: 1,
                    end: 65535,
                },
            }],
            dns_servers: vec![],
            dns_records: vec![
                DnsRecord {
                    rc_id: 205,
                    host: "ids.shiep.edu.cn".to_string(),
                    ip: "10.166.35.11".to_string(),
                },
                DnsRecord {
                    rc_id: 205,
                    host: "ids.shiep.edu.cn".to_string(),
                    ip: "10.166.35.11".to_string(),
                },
                DnsRecord {
                    rc_id: 205,
                    host: "ids.shiep.edu.cn".to_string(),
                    ip: "10.166.35.12".to_string(),
                },
                DnsRecord {
                    rc_id: 206,
                    host: "ids.shiep.edu.cn".to_string(),
                    ip: "10.166.35.12".to_string(),
                },
            ],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        assert_eq!(matcher.dns_records, 3);
        let ips = matcher
            .dns_map
            .get(&205)
            .and_then(|domains| domains.get("ids.shiep.edu.cn"))
            .unwrap();
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0].to_string(), "10.166.35.11");
        assert_eq!(ips[1].to_string(), "10.166.35.12");
        let exact_ips = matcher.dns_exact.get("ids.shiep.edu.cn").unwrap();
        assert_eq!(exact_ips.len(), 2);
        assert_eq!(exact_ips[0].to_string(), "10.166.35.11");
        assert_eq!(exact_ips[1].to_string(), "10.166.35.12");
    }

    #[test]
    fn duplicate_rules_are_deduped() {
        let table = RouteTable {
            rules: vec![
                RouteRule {
                    rc_id: 115,
                    proto: 0,
                    svc: "Other".to_string(),
                    name: "qikan".to_string(),
                    host: "qikan.chaoxing.com".to_string(),
                    port: PortRange { start: 80, end: 80 },
                },
                RouteRule {
                    rc_id: 115,
                    proto: 0,
                    svc: "Other".to_string(),
                    name: "qikan".to_string(),
                    host: "qikan.chaoxing.com".to_string(),
                    port: PortRange { start: 80, end: 80 },
                },
                RouteRule {
                    rc_id: 115,
                    proto: 0,
                    svc: "Other".to_string(),
                    name: "qikan".to_string(),
                    host: "qikan.chaoxing.com".to_string(),
                    port: PortRange {
                        start: 443,
                        end: 443,
                    },
                },
            ],
            dns_servers: vec![],
            dns_records: vec![],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        assert_eq!(matcher.rules.len(), 2);
    }

    #[test]
    fn dns_servers_are_deduped_and_trimmed() {
        let table = RouteTable {
            rules: vec![],
            dns_servers: vec![
                " 210.35.88.5 ".to_string(),
                "114.114.114.114:53".to_string(),
                "210.35.88.5:53".to_string(),
            ],
            dns_records: vec![],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        assert_eq!(
            matcher.dns_servers,
            vec![
                "210.35.88.5:53".parse().unwrap(),
                "114.114.114.114:53".parse().unwrap()
            ]
        );
    }

    fn domain_rule(rc_id: i32, host: &str) -> RouteRule {
        RouteRule {
            rc_id,
            proto: 0,
            svc: "Other".to_string(),
            name: host.to_string(),
            host: host.to_string(),
            port: PortRange {
                start: 1,
                end: 65535,
            },
        }
    }

    #[test]
    fn dns_servers_accept_ipv6_and_drop_invalid_entries() {
        let table = RouteTable {
            rules: vec![],
            dns_servers: vec![
                "::1".to_string(),
                "[::1]:53".to_string(),
                "not-a-server".to_string(),
            ],
            dns_records: vec![],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        assert_eq!(matcher.dns_servers, vec!["[::1]:53".parse().unwrap()]);
    }

    #[test]
    fn domain_hit_without_dns_map_uses_dnsserver_fallback_reason() {
        let table = RouteTable {
            rules: vec![RouteRule {
                rc_id: 205,
                proto: 0,
                svc: "Other".to_string(),
                name: "ids".to_string(),
                host: "ids.shiep.edu.cn".to_string(),
                port: PortRange {
                    start: 1,
                    end: 65535,
                },
            }],
            dns_servers: vec!["127.0.0.1:1".to_string()],
            dns_records: vec![],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        let plan = matcher.plan("ids.shiep.edu.cn", 443);
        match plan {
            RoutePlan::Fallback { reason, .. } => {
                assert!(reason.contains("dnsserver lookup failed"));
            }
            _ => panic!("expected fallback plan"),
        }
    }

    #[test]
    fn unsupported_protocol_rules_are_excluded_from_active_index() {
        let table = RouteTable {
            rules: vec![
                RouteRule {
                    rc_id: -98,
                    proto: 1,
                    svc: "".to_string(),
                    name: "udp-only".to_string(),
                    host: "210.35.88.5".to_string(),
                    port: PortRange { start: 53, end: 53 },
                },
                RouteRule {
                    rc_id: -99,
                    proto: 2,
                    svc: "".to_string(),
                    name: "icmp-only".to_string(),
                    host: "10.50.2.206".to_string(),
                    port: PortRange {
                        start: 1,
                        end: 65535,
                    },
                },
            ],
            dns_servers: vec![],
            dns_records: vec![],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        assert!(matcher.rules.is_empty());
        let plan = matcher.plan("210.35.88.5", 53);
        match plan {
            RoutePlan::Fallback { reason, .. } => {
                assert_eq!(reason, "no whitelist rule matched");
            }
            _ => panic!("expected fallback plan"),
        }
    }

    #[test]
    fn vipall_ip_rule_ignores_port_and_protocol_after_ip_hit() {
        let table = RouteTable {
            rules: vec![RouteRule {
                rc_id: 336,
                proto: 2,
                svc: "vipall".to_string(),
                name: "vip-all".to_string(),
                host: "10.50.2.206".to_string(),
                port: PortRange { start: 80, end: 80 },
            }],
            dns_servers: vec![],
            dns_records: vec![],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        let plan = matcher.plan("10.50.2.206", 443);
        match plan {
            RoutePlan::Remote {
                dial,
                rc_id,
                source,
                ..
            } => {
                assert_eq!(dial, "10.50.2.206:443");
                assert_eq!(rc_id, 336);
                assert_eq!(source, RouteSource::RuleIp);
            }
            _ => panic!("expected remote plan"),
        }
    }

    #[test]
    fn vipall_dns_data_ip_rule_ignores_port_and_protocol_after_ip_hit() {
        let table = RouteTable {
            rules: vec![RouteRule {
                rc_id: 337,
                proto: 1,
                svc: "vipall".to_string(),
                name: "vip-all-range".to_string(),
                host: "10.50.2.1~10.50.2.254".to_string(),
                port: PortRange { start: 80, end: 80 },
            }],
            dns_servers: vec![],
            dns_records: vec![DnsRecord {
                rc_id: 337,
                host: "vip.example".to_string(),
                ip: "10.50.2.206".to_string(),
            }],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        let plan = matcher.plan("vip.example", 443);
        match plan {
            RoutePlan::Remote {
                dial,
                rc_id,
                source,
                ..
            } => {
                assert_eq!(dial, "10.50.2.206:443");
                assert_eq!(rc_id, 337);
                assert_eq!(source, RouteSource::DnsDataIpRule);
            }
            _ => panic!("expected remote plan"),
        }
    }

    #[test]
    fn wildcard_protocol_rule_remains_available_for_tcp() {
        let table = RouteTable {
            rules: vec![RouteRule {
                rc_id: 335,
                proto: -1,
                svc: "Other".to_string(),
                name: "any-proto".to_string(),
                host: "10.50.2.206".to_string(),
                port: PortRange { start: 80, end: 80 },
            }],
            dns_servers: vec![],
            dns_records: vec![],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        let plan = matcher.plan("10.50.2.206", 80);
        match plan {
            RoutePlan::Remote { rc_id, .. } => {
                assert_eq!(rc_id, 335);
            }
            _ => panic!("expected remote plan"),
        }
    }

    #[test]
    fn ip_match_preserves_original_rule_order_between_exact_and_range() {
        let table = RouteTable {
            rules: vec![
                RouteRule {
                    rc_id: 1,
                    proto: 0,
                    svc: "Other".to_string(),
                    name: "range-first".to_string(),
                    host: "10.50.2.1~10.50.2.254".to_string(),
                    port: PortRange { start: 80, end: 80 },
                },
                RouteRule {
                    rc_id: 2,
                    proto: 0,
                    svc: "Other".to_string(),
                    name: "exact-second".to_string(),
                    host: "10.50.2.206".to_string(),
                    port: PortRange { start: 80, end: 80 },
                },
            ],
            dns_servers: vec![],
            dns_records: vec![],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        let plan = matcher.plan("10.50.2.206", 80);
        match plan {
            RoutePlan::Remote { rc_id, dial, .. } => {
                assert_eq!(rc_id, 1);
                assert_eq!(dial, "10.50.2.206:80");
            }
            _ => panic!("expected remote plan"),
        }
    }
}
