use crate::ports::prover::Prover;
use anyhow::{anyhow, Result};
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;
use common::crypto::poseidon::constants::PoseidonParams;
use jf_primitives::rescue::RescueParameter;
use jf_relation::gadgets::ecc::SWToTEConParam;
use plonk_prover::client::{
    circuits::{mint::MintCircuit, transfer::TransferCircuit},
    ClientPlonkCircuit,
};
use plonk_prover::primitives::circuits::kem_dem::KemDemParams;
use zk_macros::client_circuit;

const DEPTH: usize = 8;

#[client_circuit]
pub fn select_client_circuits<P, V, VSW>() -> Vec<Box<dyn ClientPlonkCircuit<P, V, VSW>>> {
    let circuit_info: Vec<Box<dyn ClientPlonkCircuit<P, V, VSW>>> = vec![
        Box::new(MintCircuit::<1>::new()),
        Box::new(MintCircuit::<2>::new()),
        Box::new(TransferCircuit::<1, 1, DEPTH>::new()),
        Box::new(TransferCircuit::<1, 2, DEPTH>::new()),
        Box::new(TransferCircuit::<2, 2, DEPTH>::new()),
        Box::new(TransferCircuit::<2, 3, DEPTH>::new()),
    ];
    circuit_info
}

#[client_circuit]
pub fn init_client_circuits<P, V, VSW, PR: Prover<P, V, VSW>>(prover: &mut PR) -> Result<()> {
    let circuit_info = select_client_circuits::<P, V, VSW>();
    for c in circuit_info {
        let keys = c
            .generate_keys()
            .map_err(|e| anyhow!("Failed to generate keys: {:?}", e))?;
        prover.store_pk(c.get_circuit_id(), keys.0);
    }
    Ok(())
}

#[client_circuit]
pub fn get_mint_circuit_from_params<P, V, VSW>(
    c: usize,
) -> Result<Box<dyn ClientPlonkCircuit<P, V, VSW>>> {
    let circuit = match c {
        1 => MintCircuit::<1>::new().as_circuit::<P, V, VSW>(),
        2 => MintCircuit::<2>::new().as_circuit::<P, V, VSW>(),
        3 => MintCircuit::<3>::new().as_circuit::<P, V, VSW>(),
        4 => MintCircuit::<4>::new().as_circuit::<P, V, VSW>(),
        5 => MintCircuit::<5>::new().as_circuit::<P, V, VSW>(),
        _ => {
            return Err(anyhow!(
                "Mint circuit with {c} commitments is not registered"
            ))
        }
    };
    Ok(circuit)
}

#[client_circuit]
pub fn get_transfer_circuit_from_params<P, V, VSW>(
    c: usize,
    n: usize,
) -> Result<Box<dyn ClientPlonkCircuit<P, V, VSW>>> {
    let circuit = match (c, n) {
        (1, 1) => TransferCircuit::<1, 1, DEPTH>::new().as_circuit::<P, V, VSW>(),
        (1, 2) => TransferCircuit::<1, 2, DEPTH>::new().as_circuit::<P, V, VSW>(),
        (2, 2) => TransferCircuit::<2, 2, DEPTH>::new().as_circuit::<P, V, VSW>(),
        (2, 3) => TransferCircuit::<2, 3, DEPTH>::new().as_circuit::<P, V, VSW>(),
        (2, 4) => TransferCircuit::<2, 4, DEPTH>::new().as_circuit::<P, V, VSW>(),
        _ => {
            return Err(anyhow!(
                "Transfer circuit with {c} commitments and {n}  nullifiers is not registered"
            ))
        }
    };
    Ok(circuit)
}

#[cfg(test)]
mod tests {
    use crate::ports::prover::Prover;
    use crate::services::prover::in_memory_prover::InMemProver;
    use crate::utils::circuits;
    use curves::pallas::PallasConfig;
    use curves::vesta::VestaConfig;
    use plonk_prover::client::circuits::mint::MintCircuit;
    use plonk_prover::client::circuits::transfer::TransferCircuit;
    use plonk_prover::client::ClientPlonkCircuit;

    #[test]
    fn test_init_client_circuit() {
        const DEPTH: usize = 8;
        let mut prover: InMemProver<PallasConfig, VestaConfig, _> = InMemProver::new();
        let pk = prover.get_pk(
            MintCircuit::<1>::new()
                .as_circuit::<PallasConfig, VestaConfig, _>()
                .get_circuit_id(),
        );

        assert!(pk.is_none());

        circuits::init_client_circuits::<PallasConfig, VestaConfig, VestaConfig, _>(&mut prover)
            .expect("Error initializing client circuits");

        let circuit_info: Vec<Box<dyn ClientPlonkCircuit<PallasConfig, VestaConfig, VestaConfig>>> = vec![
            Box::new(MintCircuit::<1>::new()),
            Box::new(MintCircuit::<2>::new()),
            Box::new(TransferCircuit::<1, 1, DEPTH>::new()),
            Box::new(TransferCircuit::<1, 2, DEPTH>::new()),
            Box::new(TransferCircuit::<2, 2, DEPTH>::new()),
            Box::new(TransferCircuit::<2, 3, DEPTH>::new()),
        ];
        circuit_info.iter().for_each(|c| {
            let pk = prover.get_pk(c.get_circuit_id());
            assert!(pk.is_some())
        });
    }
}
