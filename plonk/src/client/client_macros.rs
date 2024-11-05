#[macro_export]
macro_rules! initialize_circuits {
    ($($param:expr),+) => {{
        let mut info: Vec<(CircuitId, (ProvingKey<VestaConfig>, VerifyingKey<VestaConfig>))> = Vec::new();
        $(
            {
                const TYPE: &'static str = $param.0;
                const C: usize = $param.1;
                const N: usize = $param.2;
                if TYPE == "mint" {
                     let circuit = MintCircuit::<C>::new();
                     info.push((circuit.get_circuit_id(), client::generate_keys::<PallasConfig, VestaConfig,_, _>(&circuit).unwrap()));
                } else if TYPE == "transfer" {
                     let circuit = TransferCircuit::<C,N, DEPTH>::new();
                     info.push((circuit.get_circuit_id(), client::generate_keys::<PallasConfig, VestaConfig,_, _>(&circuit).unwrap()));
                }
            }
        )+
        info // Return the vector of circuits
    }};
}

#[cfg(test)]
mod test {

    use crate::client::circuits::{mint::MintCircuit, transfer::TransferCircuit};
    use crate::client::{self, circuits::structs::CircuitId};
    use curves::pallas::PallasConfig;
    use curves::vesta::VestaConfig;
    use jf_plonk::nightfall::ipa_structs::{ProvingKey, VerifyingKey};

    const DEPTH: usize = 8;

    #[test]
    fn test_initialize_circuits() {
        let info = initialize_circuits!(
            ("mint", 1, 0),
            ("mint", 2, 0),
            ("transfer", 1, 1),
            ("transfer", 1, 2),
            ("transfer", 2, 2),
            ("transfer", 2, 3)
        );

        let expected_circuit_ids = vec![
            "MINT_1",
            "MINT_2",
            "TRANSFER_1_1",
            "TRANSFER_1_2",
            "TRANSFER_2_2",
            "TRANSFER_2_3",
        ];
        info.into_iter()
            .enumerate()
            .for_each(|(idx, circuit_info)| {
                assert_eq!(
                    circuit_info.0,
                    CircuitId::new(expected_circuit_ids[idx].to_string())
                )
            });
    }
}
