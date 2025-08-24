use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hpcompalgo::*;
use hpcompcrypto::*;

struct LocalOracle {
    sk: PaillierPrivateKey,
    pk: PaillierPublicKey,
}
impl RemoteMultiplier for LocalOracle {
    fn mult_batch(
        &mut self,
        blinded_pairs: &[(Ciphertext, Ciphertext)],
    ) -> anyhow::Result<Vec<Ciphertext>> {
        Ok(blinded_pairs
            .iter()
            .map(|(x, y)| {
                let xv = dec(&self.sk, x);
                let yv = dec(&self.sk, y);
                enc(&self.pk, &(xv * yv), &mut rand::thread_rng())
            })
            .collect())
    }
}
impl RemoteComparator for LocalOracle {
    fn cmp_zero(&mut self, x: &Ciphertext) -> anyhow::Result<(Ciphertext, Ciphertext, Ciphertext)> {
        let v = dec(&self.sk, x);
        let lt = if v < 0 { 1 } else { 0 };
        let eq = if v == 0 { 1 } else { 0 };
        let gt = if v > 0 { 1 } else { 0 };
        Ok((
            enc(&self.pk, &lt.into(), &mut rand::thread_rng()),
            enc(&self.pk, &eq.into(), &mut rand::thread_rng()),
            enc(&self.pk, &gt.into(), &mut rand::thread_rng()),
        ))
    }
}

fn bench_single_segment(c: &mut Criterion) {
    let (pk, sk) = keygen(1024, &mut rand::thread_rng());
    let mut oracle = LocalOracle { pk: pk.clone(), sk };

    // Alice segment: (0,0) -> (10,10)
    let a = Seg {
        p: Pt {
            x: EncInt::new(enc(&pk, &0.into(), &mut rand::thread_rng())),
            y: EncInt::new(enc(&pk, &0.into(), &mut rand::thread_rng())),
        },
        q: Pt {
            x: EncInt::new(enc(&pk, &10.into(), &mut rand::thread_rng())),
            y: EncInt::new(enc(&pk, &10.into(), &mut rand::thread_rng())),
        },
    };
    // Bob segment: (5,-5) -> (5,15)
    let b = Seg {
        p: Pt {
            x: EncInt::new(enc(&pk, &5.into(), &mut rand::thread_rng())),
            y: EncInt::new(enc(&pk, &(-5).into(), &mut rand::thread_rng())),
        },
        q: Pt {
            x: EncInt::new(enc(&pk, &5.into(), &mut rand::thread_rng())),
            y: EncInt::new(enc(&pk, &15.into(), &mut rand::thread_rng())),
        },
    };

    c.bench_function("segments_intersect_encrypted_single", |bencher| {
        bencher.iter(|| {
            let mut ctx = ProtoCtx {
                pk: &pk,
                mult: &mut oracle,
                cmp: &mut oracle,
            };
            let res = segments_intersect(&a, &b, &mut ctx).unwrap();
            black_box(res);
        });
    });
}

criterion_group!(benches, bench_single_segment);
criterion_main!(benches);
