use std::process::Command;

fn run(args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_rsigncode"))
        .args(args)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The commands are parsed but not implemented yet: each one fails and names itself.
#[test]
fn every_command_reports_that_it_is_not_implemented() {
    for (args, name) in [
        (&["sign", "in", "out"][..], "sign"),
        (&["verify", "in"][..], "verify"),
        (&["extract-data", "in", "out"][..], "extract-data"),
        (
            &["attach-signature", "sig", "in", "out"][..],
            "attach-signature",
        ),
        (&["extract-signature", "in", "out"][..], "extract-signature"),
        (&["remove-signature", "in", "out"][..], "remove-signature"),
        (&["add", "in", "out"][..], "add"),
    ] {
        let (ok, stderr) = run(args);
        assert!(!ok, "{name} succeeded");
        assert!(
            stderr.contains(&format!("`{name}` is not implemented")),
            "{stderr}"
        );
    }
}

#[test]
fn an_unknown_command_is_rejected() {
    let (ok, _) = run(&["nope"]);
    assert!(!ok);
}
