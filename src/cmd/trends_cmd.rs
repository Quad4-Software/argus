//! `argus trends <path>` - diff the latest stored scan vs the previous
//! one for a root: new findings, fixed findings, persistent count.

use crate::finding::Report;
use crate::store;

pub(crate) fn trends_cmd(root: &str, report: &mut Report) {
    match store::trend(root) {
        Ok(Some((cur, prev))) => {
            let cur_f = store::scan_findings(cur.id);
            let (new, fixed) = if let Some(ref p) = prev {
                let prev_f = store::scan_findings(p.id);
                let prev_fps: std::collections::HashSet<&String> =
                    prev_f.iter().map(|f| &f.0).collect();
                let cur_fps: std::collections::HashSet<&String> =
                    cur_f.iter().map(|f| &f.0).collect();
                (
                    cur_f.iter().filter(|f| !prev_fps.contains(&f.0)).count(),
                    prev_f.iter().filter(|f| !cur_fps.contains(&f.0)).count(),
                )
            } else {
                (cur_f.len(), 0)
            };
            let delta = if let Some(p) = &prev {
                format!(" ({}s apart)", cur.ts.saturating_sub(p.ts))
            } else {
                String::new()
            };
            println!(
                "{}: {} scans stored | latest {} findings over {} files | +{} new | -{} fixed | {} persistent{delta}",
                root,
                store::scan_count(root),
                cur.findings,
                cur.files,
                new,
                fixed,
                cur.findings - new as i64,
            );
        }
        Ok(None) => {
            report.errors.push(format!(
                "no stored scans for {root} - run `argus scan --store` first"
            ));
        }
        Err(e) => report.errors.push(e),
    }
}
