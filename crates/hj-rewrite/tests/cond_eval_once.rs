//! A rule's conds run once per rule (#980): a passing cond pre-screen is final, and
//! one evaluation reuses its last `%{REQUEST_FILENAME}` expansion and file test.
//! The counts pin the work; the outcomes pin that nothing else moved.

use std::cell::Cell;
use std::path::Path;

use hj_rewrite::{
    FileTests, HeaderLookup, RewriteInput, RewriteOutcome, RuleSet, StatSource, evaluate,
};

const FRONT_CONTROLLER: &str = r#"
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} -f [OR]
RewriteCond %{REQUEST_FILENAME} -l [OR]
RewriteCond %{REQUEST_FILENAME} -d
RewriteRule ^.*$ - [NC,L]
RewriteRule ^.*$ index.php [NC,L]
"#;

const BUILDS: &str = r#"
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteRule ^(.*)$ /index.php [L,QSA]
"#;

fn counting_eval(
    rules: &str,
    uri: &str,
    prefix: Option<&str>,
    exists: &dyn Fn(&Path) -> Option<FileTests>,
) -> (RewriteOutcome, Vec<String>) {
    counting_eval_at("/docroot", rules, uri, prefix, exists)
}

fn counting_eval_at(
    docroot: &str,
    rules: &str,
    uri: &str,
    prefix: Option<&str>,
    exists: &dyn Fn(&Path) -> Option<FileTests>,
) -> (RewriteOutcome, Vec<String>) {
    let rs = RuleSet::parse(rules).expect("parse");
    let seen = std::cell::RefCell::new(Vec::new());
    let stat = |p: &Path| {
        seen.borrow_mut().push(p.to_string_lossy().into_owned());
        exists(p)
    };
    let mut input = RewriteInput::new(uri.to_string(), docroot);
    input.per_directory_prefix = prefix.map(str::to_string);
    input.stat = StatSource::LiveTests(&stat);
    let outcome = evaluate(&rs, &input);
    drop(input);
    (outcome, seen.into_inner())
}

fn dir_tests() -> FileTests {
    FileTests {
        is_dir: true,
        exists: true,
        ..FileTests::default()
    }
}

/// `dir` (with or without its trailing slash) is a directory; nothing else exists.
fn only_dir(dir: &'static str) -> impl Fn(&Path) -> Option<FileTests> {
    move |p: &Path| (p.to_str().map(|p| p.trim_end_matches('/')) == Some(dir)).then(dir_tests)
}

fn front_controller_verdict(outcome: &RewriteOutcome) -> &'static str {
    match outcome {
        RewriteOutcome::Unchanged { .. } => "pass-through",
        RewriteOutcome::Rewritten { new_uri, .. } if new_uri == "/index.php" => "front-controller",
        other => panic!("unexpected front-controller outcome {other:?}"),
    }
}

#[test]
fn front_controller_on_a_missing_path_stats_each_path_once() {
    let (outcome, seen) = counting_eval(FRONT_CONTROLLER, "/threads/x.1/", Some(""), &|_| None);
    // The PATH_INFO walk's two lookups, then one file test shared by -f/-l/-d
    // (previously 3 lookups per cond: 9).
    assert_eq!(
        seen,
        [
            "/docroot/threads/x.1",
            "/docroot/threads",
            "/docroot/threads/x.1/"
        ]
    );
    match outcome {
        RewriteOutcome::Rewritten { new_uri, .. } => assert_eq!(new_uri, "/index.php"),
        other => panic!("front controller must rewrite, got {other:?}"),
    }
}

#[test]
fn front_controller_on_an_existing_directory_still_passes_through() {
    let dir = |p: &Path| {
        (p == Path::new("/docroot/styles") || p == Path::new("/docroot/styles/")).then_some(
            FileTests {
                is_dir: true,
                exists: true,
                ..FileTests::default()
            },
        )
    };
    let (outcome, seen) = counting_eval(FRONT_CONTROLLER, "/styles/", Some(""), &dir);
    assert_eq!(seen, ["/docroot/styles", "/docroot/styles/"]);
    assert!(
        matches!(outcome, RewriteOutcome::Unchanged { .. }),
        "{outcome:?}"
    );
}

#[test]
fn passing_prescreen_is_not_re_evaluated() {
    let dir = |p: &Path| {
        (p == Path::new("/docroot/builds")).then_some(FileTests {
            is_dir: true,
            exists: true,
            ..FileTests::default()
        })
    };
    let (outcome, seen) =
        counting_eval(BUILDS, "/builds/windows11/26100.1/", Some("builds/"), &dir);
    // One cond evaluation: the walk's three lookups plus the `!-f` test (was 8).
    assert_eq!(seen.len(), 4, "{seen:?}");
    match outcome {
        RewriteOutcome::Rewritten { new_uri, .. } => assert_eq!(new_uri, "/index.php"),
        other => panic!("missing build page must reach the front controller, got {other:?}"),
    }
}

#[test]
fn passing_header_cond_reads_the_header_once() {
    let rs = RuleSet::parse(
        "RewriteEngine On\n\
         RewriteCond %{HTTP_USER_AGENT} (Googlebot|Bingbot)\n\
         RewriteRule .* - [E=KNOWN_CRAWLER:1]\n",
    )
    .expect("parse");
    let reads = Cell::new(0);
    let lookup = |name: &str| {
        reads.set(reads.get() + 1);
        name.eq_ignore_ascii_case("User-Agent")
            .then(|| "Mozilla/5.0 (compatible; Googlebot/2.1)".to_string())
    };
    let mut input = RewriteInput::new("/threads/x.1/".to_string(), "/docroot");
    input.header_lookup = Some(HeaderLookup(&lookup));
    match evaluate(&rs, &input) {
        RewriteOutcome::Unchanged { env, .. } => {
            assert_eq!(env, [("KNOWN_CRAWLER".to_string(), "1".to_string())]);
        }
        other => panic!("crawler cond must set env, got {other:?}"),
    }
    assert_eq!(reads.get(), 1);
}

fn eval(rules: &str, uri: &str, host: &str, query: &str) -> RewriteOutcome {
    let rs = RuleSet::parse(rules).expect("parse");
    let input = RewriteInput::new(uri.to_string(), "/docroot")
        .host(host.to_string())
        .query(query.to_string());
    evaluate(&rs, &input)
}

#[test]
fn prescreened_cond_captures_reach_the_substitution() {
    let rules = "RewriteEngine On\n\
                 RewriteCond %{HTTP_HOST} ^www\\.(.+)$ [NC]\n\
                 RewriteRule ^(.*)$ https://%1/$1 [R=301,L]\n";
    match eval(rules, "/a/b", "www.example.com", "") {
        RewriteOutcome::Redirect { code, location, .. } => {
            assert_eq!(code, 301);
            assert_eq!(location, "https://example.com/a/b");
        }
        other => panic!("www host must redirect, got {other:?}"),
    }
    assert!(matches!(
        eval(rules, "/a/b", "example.com", ""),
        RewriteOutcome::Unchanged { .. }
    ));
}

#[test]
fn prescreened_or_group_keeps_the_first_passing_members_captures() {
    let rules = "RewriteEngine On\n\
                 RewriteCond %{QUERY_STRING} (?:^|&)p=(\\d+) [OR]\n\
                 RewriteCond %{QUERY_STRING} (?:^|&)id=(\\d+)\n\
                 RewriteRule ^/?item$ /show/%1? [L]\n";
    for (query, want) in [("id=7", "/show/7"), ("p=3&id=7", "/show/3")] {
        match eval(rules, "/item", "example.com", query) {
            RewriteOutcome::Rewritten {
                new_uri, new_query, ..
            } => {
                assert_eq!(new_uri, want, "{query}");
                assert_eq!(new_query, None, "{query}");
            }
            other => panic!("{query}: expected a rewrite, got {other:?}"),
        }
    }
}

#[test]
fn rule_backref_conds_still_see_the_pattern_captures() {
    let rules = "RewriteEngine On\n\
                 RewriteCond $1 !^skip/\n\
                 RewriteCond %{HTTP_HOST} ^(.+)$\n\
                 RewriteRule ^/?(.*)$ /x/%1/$1 [L]\n";
    match eval(rules, "/a/b", "h.test", "") {
        RewriteOutcome::Rewritten { new_uri, .. } => assert_eq!(new_uri, "/x/h.test/a/b"),
        other => panic!("expected a rewrite, got {other:?}"),
    }
    assert!(matches!(
        eval(rules, "/skip/b", "h.test", ""),
        RewriteOutcome::Unchanged { .. }
    ));
}

/// The memo is scoped to one `evaluate` (#980): back-to-back evaluations of one URI
/// on one thread, under other docroots or stat sources, stat their own paths and
/// reach their own verdicts. A memo surviving a call would hand the next one the
/// previous docroot's `%{REQUEST_FILENAME}` (keyed by URI) or file test.
#[test]
fn sequential_evaluations_never_reuse_each_others_stats() {
    let uri = "/threads/x.1/";
    let walked = |root: &str| {
        vec![
            format!("{root}/threads/x.1"),
            format!("{root}/threads"),
            format!("{root}/threads/x.1/"),
        ]
    };
    let none = |_: &Path| None;

    let (outcome, seen) = counting_eval_at(
        "/a",
        FRONT_CONTROLLER,
        uri,
        Some(""),
        &only_dir("/a/threads/x.1"),
    );
    assert_eq!(front_controller_verdict(&outcome), "pass-through");
    assert_eq!(seen, ["/a/threads/x.1", "/a/threads/x.1/"]);

    let (outcome, seen) = counting_eval_at("/b", FRONT_CONTROLLER, uri, Some(""), &none);
    assert_eq!(front_controller_verdict(&outcome), "front-controller");
    assert_eq!(seen, walked("/b"));

    // Same docroot as the first call, but the directory is gone now.
    let (outcome, seen) = counting_eval_at("/a", FRONT_CONTROLLER, uri, Some(""), &none);
    assert_eq!(front_controller_verdict(&outcome), "front-controller");
    assert_eq!(seen, walked("/a"));

    // A precomputed source never consults (or fills) the memo.
    let rs = RuleSet::parse(FRONT_CONTROLLER).expect("parse");
    let mut input = RewriteInput::new(uri.to_string(), "/a");
    input.per_directory_prefix = Some(String::new());
    input.stat = StatSource::Precomputed(dir_tests());
    assert_eq!(
        front_controller_verdict(&evaluate(&rs, &input)),
        "pass-through"
    );

    // Real metadata after the synthetic sources: a docroot where the path is a
    // directory on disk, then one where it is missing.
    let root = std::env::temp_dir().join(format!("hj-rewrite-fs-memo-{}", std::process::id()));
    let present = root.join("present");
    let missing = root.join("missing");
    std::fs::create_dir_all(present.join("threads/x.1")).unwrap();
    std::fs::create_dir_all(&missing).unwrap();
    let metadata = |p: &Path| std::fs::metadata(p).ok();
    for (docroot, want) in [
        (&present, "pass-through"),
        (&missing, "front-controller"),
        (&present, "pass-through"),
    ] {
        let mut input = RewriteInput::new(uri.to_string(), docroot.clone());
        input.per_directory_prefix = Some(String::new());
        input.stat = StatSource::Live(&metadata);
        assert_eq!(
            front_controller_verdict(&evaluate(&rs, &input)),
            want,
            "{}",
            docroot.display()
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// `%{REQUEST_FILENAME}` is expanded into an env value (memoized), a header is
/// read outside any RewriteCond, then a file test reuses the expansion.
const NESTABLE: &str = r#"
RewriteEngine On
RewriteRule ^ - [E=FILE:%{REQUEST_FILENAME}]
RewriteRule ^ - [E=UA:%{HTTP_USER_AGENT}]
RewriteCond %{REQUEST_FILENAME} -d
RewriteRule ^ - [E=DIR:1]
"#;

#[derive(Clone, Copy, Debug, PartialEq)]
enum NestAt {
    /// Inside the outer's PATH_INFO walk stat: its memo is still being filled.
    WalkStat,
    /// Inside the outer's header lookup: its memo already holds the expansion.
    HeaderLookup,
}

fn env_of(outcome: RewriteOutcome) -> Vec<(String, String)> {
    match outcome {
        RewriteOutcome::Unchanged { env, .. } => env,
        other => panic!("env-only rules must not rewrite, got {other:?}"),
    }
}

/// An evaluation nested inside another one's callback (same thread, same URI, its
/// own docroot and stat source) neither reads the outer memo nor leaves its own
/// behind, whether the outer memo is still empty or already filled (#980).
#[test]
fn nested_evaluation_keeps_its_own_memo() {
    let rs = RuleSet::parse(NESTABLE).expect("parse");
    let uri = "/threads/x.1/";
    for nest in [NestAt::WalkStat, NestAt::HeaderLookup] {
        let outer_seen = std::cell::RefCell::new(Vec::<String>::new());
        let inner_seen = std::cell::RefCell::new(Vec::<String>::new());
        let inner_env = std::cell::RefCell::new(None);
        let inner_stat = |p: &Path| {
            inner_seen
                .borrow_mut()
                .push(p.to_string_lossy().into_owned());
            None
        };
        let run_inner = || {
            let mut input = RewriteInput::new(uri.to_string(), "/inner");
            input.stat = StatSource::LiveTests(&inner_stat);
            *inner_env.borrow_mut() = Some(env_of(evaluate(&rs, &input)));
        };
        let outer_dir = only_dir("/outer/threads/x.1");
        let outer_stat = |p: &Path| {
            let first = {
                let mut seen = outer_seen.borrow_mut();
                seen.push(p.to_string_lossy().into_owned());
                seen.len() == 1
            };
            if first && nest == NestAt::WalkStat {
                run_inner();
            }
            outer_dir(p)
        };
        let lookup = |name: &str| {
            if !name.eq_ignore_ascii_case("User-Agent") {
                return None;
            }
            if nest == NestAt::HeaderLookup {
                run_inner();
            }
            Some("outer-agent".to_string())
        };
        let mut input = RewriteInput::new(uri.to_string(), "/outer");
        input.stat = StatSource::LiveTests(&outer_stat);
        input.header_lookup = Some(HeaderLookup(&lookup));
        let outer_env = env_of(evaluate(&rs, &input));
        drop(input);

        let pair = |k: &str, v: &str| (k.to_string(), v.to_string());
        let mut outer_env = outer_env;
        outer_env.sort();
        assert_eq!(
            outer_env,
            [
                pair("DIR", "1"),
                pair("FILE", "/outer/threads/x.1/"),
                pair("UA", "outer-agent"),
            ],
            "{nest:?}"
        );
        let inner_env = inner_env.into_inner().expect("the nested evaluation ran");
        assert!(
            inner_env.contains(&pair("FILE", "/inner/threads/x.1/")),
            "{nest:?}: {inner_env:?}"
        );
        assert!(
            !inner_env.iter().any(|(k, _)| k == "DIR"),
            "{nest:?}: {inner_env:?}"
        );
        // The nested evaluation memoized its own walk for its own file test.
        assert_eq!(
            inner_seen.into_inner(),
            [
                "/inner/threads/x.1",
                "/inner/threads",
                "/inner/threads/x.1/"
            ],
            "{nest:?}"
        );
        let outer_seen = outer_seen.into_inner();
        assert!(
            outer_seen
                .iter()
                .all(|p| p.starts_with("/outer/threads/x.1")),
            "{nest:?}: {outer_seen:?}"
        );
        assert!(
            outer_seen.iter().any(|p| p == "/outer/threads/x.1/"),
            "{nest:?}: the outer file test must stat its own path: {outer_seen:?}"
        );
    }
}

/// A callback that re-enters `evaluate` while a RewriteCond is file-testing gets
/// working scratch buffers instead of a "RefCell already borrowed" panic (#1006),
/// and both evaluations reach their own verdicts.
#[test]
fn evaluate_re_entered_from_a_cond_file_test_does_not_panic() {
    let rs = RuleSet::parse(FRONT_CONTROLLER).expect("parse");
    let inner_verdict = Cell::new("not run");
    let inner_stat = |_: &Path| None;
    let outer_dir = only_dir("/outer/threads/x.1");
    let outer_stat = |p: &Path| {
        if inner_verdict.get() == "not run" {
            let mut input = RewriteInput::new("/threads/x.1/".to_string(), "/inner");
            input.stat = StatSource::LiveTests(&inner_stat);
            inner_verdict.set(front_controller_verdict(&evaluate(&rs, &input)));
        }
        outer_dir(p)
    };
    let mut input = RewriteInput::new("/threads/x.1/".to_string(), "/outer");
    input.stat = StatSource::LiveTests(&outer_stat);
    let outer = evaluate(&rs, &input);
    drop(input);
    assert_eq!(front_controller_verdict(&outer), "pass-through");
    assert_eq!(inner_verdict.get(), "front-controller");
}
