fn main() {
    println!("cargo:rerun-if-changed=../ui/index.html");
    println!("cargo:rerun-if-changed=../ui/app.js");
    println!("cargo:rerun-if-changed=../ui/styles.css");
    tauri_build::build()
}
