//! Pure-Rust ports of the detectors the planner may place in a plan.
//!
//! Only a detector whose entire decision is a stateless scan of top-level
//! string arguments belongs here. Each port must return exactly what the
//! Python factory returns - the same verdict (BLOCK), the same `policy_id`,
//! the same `"<policy_id>: <argument>"` reason, and the argument it matched as
//! `attributed_to`. The planner lists these names in `NATIVE_DETECTORS`; a
//! policy using any other detector stays on the Python engine, so a partial
//! port cannot change an answer.
//!
//! Deliberately absent: anything parameterised (`canary_leak_guard`), anything
//! that parses (`destructive_command_guard`), anything with counters or time
//! (`*_rate_limiter`, `duplicate_call_loop_guard`), and every redactor - those
//! return MODIFY, which the plan does not represent.
//!
//! The Python originals and their docstrings are the specification:
//! `interlock/detectors/{ansi_escape_output_guard,crlf_header_injection_guard,
//! download_extension_guard,code_eval_exec_guard}.py`.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;
use unicode_normalization::UnicodeNormalization;

use crate::Event;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeDetector {
    AnsiEscapeOutput,
    CrlfHeaderInjection,
    DownloadExtension,
    CodeEvalExec,
}

impl NativeDetector {
    /// The canonical plan name. The planner accepts the bare factory name and
    /// the `module.factory` spelling, and emits this one.
    pub fn parse(name: &str) -> Option<NativeDetector> {
        match name {
            "ansi_escape_output_guard" => Some(NativeDetector::AnsiEscapeOutput),
            "crlf_header_injection_guard" => Some(NativeDetector::CrlfHeaderInjection),
            "download_extension_guard" => Some(NativeDetector::DownloadExtension),
            "code_eval_exec_guard" => Some(NativeDetector::CodeEvalExec),
            _ => None,
        }
    }

    /// The `policy_id` a decision from this detector carries.
    pub fn policy_id(self) -> &'static str {
        match self {
            NativeDetector::AnsiEscapeOutput => "ansi_escape_output",
            NativeDetector::CrlfHeaderInjection => "crlf_injection",
            NativeDetector::DownloadExtension => "download_extension",
            NativeDetector::CodeEvalExec => "code_eval_exec",
        }
    }

    fn regex(self) -> &'static Regex {
        static ANSI: OnceLock<Regex> = OnceLock::new();
        static CRLF: OnceLock<Regex> = OnceLock::new();
        static DOWNLOAD: OnceLock<Regex> = OnceLock::new();
        static CODE: OnceLock<Regex> = OnceLock::new();
        match self {
            NativeDetector::AnsiEscapeOutput => ANSI.get_or_init(|| {
                // Live introducers (ESC[, C1 CSI) and the escaped spellings.
                Regex::new(r"(?:\x1b\[|\\x1b\[|\\033\[|\\u001b\[|\x9b)")
                    .expect("static ANSI pattern")
            }),
            NativeDetector::CrlfHeaderInjection => CRLF.get_or_init(|| {
                Regex::new(r"(?:%0d%0a|%0a|%0d|\\r\\n|\\n\\r)")
                    .expect("static CRLF pattern")
            }),
            NativeDetector::DownloadExtension => DOWNLOAD.get_or_init(|| {
                // Python's `$` also matches before a final newline; Rust's
                // `$` is end-of-haystack, so `\n$` restores the Python form.
                Regex::new(
                    r"(?i)\.(?:sh|exe|bat|cmd|ps1|scr|jar|msi|dll|dylib|so)(?:$|\n$|[?#])",
                )
                .expect("static download-extension pattern")
            }),
            NativeDetector::CodeEvalExec => CODE.get_or_init(|| {
                Regex::new(r"\b(?:eval|exec|compile|__import__)\s*\(")
                    .expect("static code-eval pattern")
            }),
        }
    }

    fn matches(self, text: &str) -> bool {
        if self.regex().is_match(text) {
            return true;
        }
        if self != NativeDetector::CodeEvalExec {
            return false;
        }
        // Python reads identifiers in NFKC form, so the fullwidth `ｅｖａｌ(`
        // is the builtin. Scan the normalized text only when it differs.
        let normalized: String = text.nfkc().collect();
        normalized != text && self.regex().is_match(&normalized)
    }

    /// The first matching top-level string argument, in document order.
    ///
    /// `None` means "no opinion" - a non-object `args` or no string match.
    /// The Python factories never raise on odd input; neither does this.
    pub fn scan(self, event: &Event) -> Option<String> {
        let args = event.args().as_object()?;
        for (name, value) in args {
            if let Value::String(text) = value {
                if self.matches(text) {
                    return Some(name.clone());
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Event;
    use serde_json::json;

    fn event(args: serde_json::Value) -> Event {
        Event::from_value(&json!({"action": "Bash", "args": args})).unwrap()
    }

    #[test]
    fn ansi_covers_live_and_escaped_forms() {
        let detector = NativeDetector::AnsiEscapeOutput;
        for text in [
            "x\u{1b}[31mred",
            "x\\x1b[31mred",
            "x\\033[31mred",
            "x\\u001b[31mred",
            "x\u{9b}31m",
        ] {
            assert_eq!(
                detector.scan(&event(json!({"command": text}))),
                Some("command".to_string()),
                "{text:?}"
            );
        }
        assert_eq!(detector.scan(&event(json!({"command": "plain"}))), None);
        assert_eq!(detector.scan(&event(json!({"n": 1, "nested": {"s": "\u{1b}["}}))), None);
    }

    #[test]
    fn crlf_and_download_match_their_python_patterns() {
        let crlf = NativeDetector::CrlfHeaderInjection;
        for text in ["a%0d%0ab", "a%0ab", "a%0db", "a\\r\\nb", "a\\n\\rb"] {
            assert_eq!(crlf.scan(&event(json!({"v": text}))), Some("v".to_string()));
        }
        assert_eq!(crlf.scan(&event(json!({"v": "a%0Ab"}))), None);

        let download = NativeDetector::DownloadExtension;
        for text in ["x/payload.sh", "x/payload.SH?t=1", "x/payload.exe#frag"] {
            assert_eq!(
                download.scan(&event(json!({"path": text}))),
                Some("path".to_string()),
                "{text:?}"
            );
        }
        for text in ["x/payload.shell", "x/payload.sh.txt", "notes.txt"] {
            assert_eq!(download.scan(&event(json!({"path": text}))), None, "{text:?}");
        }
        // Python's `$` accepts a final newline; so must this port.
        assert_eq!(
            download.scan(&event(json!({"path": "x/payload.sh\n"}))),
            Some("path".to_string())
        );
    }

    #[test]
    fn code_eval_scans_raw_then_nfkc() {
        let detector = NativeDetector::CodeEvalExec;
        assert_eq!(
            detector.scan(&event(json!({"code": "x = eval(payload)"}))),
            Some("code".to_string())
        );
        assert_eq!(
            detector.scan(&event(json!({"code": "ｘ = ｅｖａｌ(payload)"}))),
            Some("code".to_string())
        );
        assert_eq!(detector.scan(&event(json!({"code": "myeval(x)"}))), None);
        assert_eq!(detector.scan(&event(json!({"code": "EVAL(x)"}))), None);
    }

    #[test]
    fn first_matching_argument_in_document_order_wins() {
        let detector = NativeDetector::DownloadExtension;
        let value = json!({"second": "a.sh", "first": "b.sh"});
        assert_eq!(detector.scan(&event(value)), Some("second".to_string()));
    }
}
