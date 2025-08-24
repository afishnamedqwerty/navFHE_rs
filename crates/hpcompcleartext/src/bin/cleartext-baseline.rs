use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
struct Opt {
    route_a: String,
    route_b: String,
}

#[derive(Clone, Copy)]
struct Pt {
    x: i64,
    y: i64,
}
#[derive(Clone, Copy)]
struct Seg {
    p: Pt,
    q: Pt,
}

fn read_route(path: &str) -> Result<Vec<Seg>> {
    let txt = std::fs::read_to_string(path)?;
    let mut pts = vec![];
    for line in txt.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        let x: i64 = it.next().unwrap().parse()?;
        let y: i64 = it.next().unwrap().parse()?;
        pts.push(Pt { x, y });
    }
    let segs = pts.windows(2).map(|w| Seg { p: w[0], q: w[1] }).collect();
    Ok(segs)
}

fn orient(p: Pt, q: Pt, r: Pt) -> i64 {
    (q.y - p.y) * (r.x - q.x) - (q.x - p.x) * (r.y - q.y)
}
fn on_segment(p: Pt, a: Pt, b: Pt) -> bool {
    let minx = a.x.min(b.x);
    let maxx = a.x.max(b.x);
    let miny = a.y.min(b.y);
    let maxy = a.y.max(b.y);
    p.x >= minx && p.x <= maxx && p.y >= miny && p.y <= maxy
}
fn intersects(a: Seg, b: Seg) -> bool {
    let o1 = orient(a.p, a.q, b.p);
    let o2 = orient(a.p, a.q, b.q);
    let o3 = orient(b.p, b.q, a.p);
    let o4 = orient(b.p, b.q, a.q);
    if (o1 > 0 && o2 < 0 || o1 < 0 && o2 > 0) && (o3 > 0 && o4 < 0 || o3 < 0 && o4 > 0) {
        return true;
    }
    if o1 == 0 && on_segment(b.p, a.p, a.q) {
        return true;
    }
    if o2 == 0 && on_segment(b.q, a.p, a.q) {
        return true;
    }
    if o3 == 0 && on_segment(a.p, b.p, b.q) {
        return true;
    }
    if o4 == 0 && on_segment(a.q, b.p, b.q) {
        return true;
    }
    false
}

fn main() -> Result<()> {
    let opt = Opt::parse();
    let asgs = read_route(&opt.route_a)?;
    let bsgs = read_route(&opt.route_b)?;

    for (i, a) in asgs.iter().enumerate() {
        let mut hit = false;
        for b in &bsgs {
            if intersects(*a, *b) {
                hit = true;
                break;
            }
        }
        println!("seg {}: {}", i, if hit { 1 } else { 0 });
    }
    Ok(())
}
