use ark_ff::PrimeField;
use curves::pallas::Fq;
use poseidon_paramgen::v1::generate;
/// This function generates the constants for the poseidon hash function
fn main() {
    let mut mds_arr = Vec::new();
    let mut ark_arr = Vec::new();
    // For input length 1 - 8 (the extra is for the output)
    (2..=9).for_each(|i| {
        let params = generate::<Fq>(128, i, Fq::MODULUS, false);
        let round_numbers = params.rounds;
        ark_std::println!("rounds: {:?}", round_numbers);
        let arc = params.arc;
        ark_std::println!("arc cols: {}", arc.0.n_cols);
        ark_std::println!("arc rows: {}", arc.0.n_rows);
        ark_std::println!("arc elements: {}", arc.0.elements.len());
        let str_ark: Vec<String> = arc.0.elements.iter().map(|x| x.to_string()).collect();
        let mds = params.mds;
        ark_std::println!("cols: {}", mds.0 .0.n_cols);
        let mds_col = mds.0 .0.n_cols;
        let mds_row = mds.0 .0.n_rows;
        let mut str_mds: Vec<Vec<String>> = Vec::new();
        str_mds.resize(mds_row, Vec::new());
        for i in 0..mds_row {
            str_mds[i].resize(mds_col, String::new());
        }
        ark_std::println!("rows: {}", mds.0 .0.n_rows);
        ark_std::println!("elements: {}", mds.0 .0.elements.len());
        for i in 0..mds_row {
            for j in 0..mds_col {
                str_mds[i][j] = mds.0 .0.elements[mds_col * i + j].to_string();
            }
        }
        mds_arr.push(str_mds);
        ark_arr.push(str_ark);
    });

    ark_std::fs::write("pallas_fq_mds.txt", format!("{:?}", mds_arr)).unwrap();
    ark_std::fs::write("pallas_fq.txt", format!("{:?}", ark_arr)).unwrap();
}
