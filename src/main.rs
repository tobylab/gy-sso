mod guan_yuan_sso;

fn main() {
    if let Err(err) = guan_yuan_sso::run_demo() {
        eprintln!("SSO demo skipped: {err}");
    }
}
