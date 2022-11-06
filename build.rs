use winres;

fn main() {
    let mut res = winres::WindowsResource::new();
    res.set_icon("pv.ico");
    res.compile().unwrap();
}
