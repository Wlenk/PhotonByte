pub fn normalize_domain(s: &str) -> String {
    let s = s.trim().to_ascii_lowercase();
    if s.ends_with('.') { s[..s.len()-1].to_string() } else { s }
}

pub fn domain_in_list(domain: &str, list: &[String]) -> bool {
    let d = normalize_domain(domain);
    for raw in list {
        let e = normalize_domain(raw);
        if e.is_empty() { continue; }

        if e.starts_with("*.") {
            let base = &e[2..];
            if d == base || d.ends_with(&format!(".{}", base)) { return true; }
        } else if e.starts_with('.') {
            let base = &e[1..];
            if d == base || d.ends_with(&format!(".{}", base)) { return true; }
        } else {
            if d == e || d.ends_with(&format!(".{}", e)) { return true; }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn t() {
        let list = vec![
            "baidu.com".into(),
            "*.evil.test".into(),
            ".legacy.org".into(),
        ];
        assert!(domain_in_list("baidu.com.", &list));
        assert!(domain_in_list("www.baidu.com", &list));
        assert!(domain_in_list("sub.evil.test", &list));
        assert!(domain_in_list("evil.test", &list));
        assert!(domain_in_list("legacy.org", &list));
        assert!(domain_in_list("a.legacy.org", &list));
        assert!(!domain_in_list("notbaidu.com", &list));
    }
}