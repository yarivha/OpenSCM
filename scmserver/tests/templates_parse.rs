// templates_parse.rs — startup smoke test for the embedded Tera templates.
//
// init_tera() parses every embedded template up front; if any template has a
// syntax error the server panics/exits at boot (a crash-loop in production,
// surfacing as 502 behind the proxy). This guards the easy-to-miss case of a
// Tera token (`{% … %}`, `{{ … }}`, `{# … #}`) accidentally embedded in inline
// JavaScript — e.g. a literal "{% block scripts %}" inside a JS comment, which
// Tera parses as a real tag and unbalances the document.

// Every embedded template must parse cleanly, so a broken template fails CI
// instead of the production server at startup.
#[test]
fn all_embedded_templates_parse() {
    scmserver::init_tera().expect("all embedded templates must parse under Tera");
}
