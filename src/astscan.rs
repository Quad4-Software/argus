// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

//! AST-aware rules via tree-sitter: `type = "ast"` rules carry a tree-sitter
//! S-expression query and a language. Matching happens on the parse tree, so
//! comments and string literals never produce hits - the systematic false
//! positives of line-regex SAST.

/// Languages with a compiled grammar.
/// (pub because CompiledKind is pub; the module itself stays crate-internal)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AstLang {
    JavaScript,
    TypeScript,
    /// .tsx/.jsx: TypeScript grammar compiled with JSX production enabled.
    /// Parsing tsx under LANGUAGE_TYPESCRIPT silently degrades.
    Tsx,
    Python,
    Go,
    Rust,
}

impl AstLang {
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "javascript" | "js" => Some(Self::JavaScript),
            "typescript" | "ts" => Some(Self::TypeScript),
            "tsx" => Some(Self::Tsx),
            "python" | "py" => Some(Self::Python),
            "go" => Some(Self::Go),
            "rust" | "rs" => Some(Self::Rust),
            _ => None,
        }
    }

    /// File extensions (no dot) this language handles.
    pub fn extensions(self) -> &'static [&'static str] {
        match self {
            Self::JavaScript => &["js", "jsx", "mjs", "cjs"],
            Self::TypeScript => &["ts", "mts", "cts"],
            Self::Tsx => &["tsx"],
            Self::Python => &["py", "pyw"],
            Self::Go => &["go"],
            Self::Rust => &["rs"],
        }
    }

    pub fn grammar(self) -> tree_sitter::Language {
        match self {
            Self::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Self::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Self::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
            Self::Python => tree_sitter_python::LANGUAGE.into(),
            Self::Go => tree_sitter_go::LANGUAGE.into(),
            Self::Rust => tree_sitter_rust::LANGUAGE.into(),
        }
    }
}

/// True when a rule written for `rule_lang` should run on a file whose
/// language is `file_lang`. typescript rules also cover tsx sources;
/// javascript rules already see jsx through the JS grammar.
pub(crate) fn covers(rule_lang: AstLang, file_lang: AstLang) -> bool {
    rule_lang == file_lang || (rule_lang == AstLang::TypeScript && file_lang == AstLang::Tsx)
}

/// Language for a repo-relative path, by extension.
pub(crate) fn lang_for_path(rel: &str) -> Option<AstLang> {
    let ext = rel.rsplit('.').next()?.to_lowercase();
    for l in [
        AstLang::JavaScript,
        AstLang::TypeScript,
        AstLang::Tsx,
        AstLang::Python,
        AstLang::Go,
        AstLang::Rust,
    ] {
        if l.extensions().contains(&ext.as_str()) {
            return Some(l);
        }
    }
    None
}

/// Parse `text` as `lang`. Tree-sitter never fails hard - it produces an
/// error-flagged tree, which is fine for pattern matching.
pub(crate) fn parse(lang: AstLang, text: &str) -> Option<tree_sitter::Tree> {
    let mut p = tree_sitter::Parser::new();
    p.set_language(&lang.grammar()).ok()?;
    p.parse(text, None)
}
