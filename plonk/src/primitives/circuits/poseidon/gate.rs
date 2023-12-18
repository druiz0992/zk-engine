use ark_ff::{Field, PrimeField};
use jf_relation::{constants::GATE_WIDTH, gates::Gate};

#[derive(Debug, Clone)]
pub struct FullRoundGate<F> {
    pub matrix_vector: Vec<F>,
    pub constant: F,
}

impl<F: PrimeField> Gate<F> for FullRoundGate<F> {
    fn name(&self) -> &'static str {
        "Full round, S-box and mix gate"
    }
    // Calculate w_0^5 + w_1^5 + w_2^5 + w_3^5
    fn q_hash(&self) -> [F; GATE_WIDTH] {
        [
            self.matrix_vector[0],
            self.matrix_vector[1],
            self.matrix_vector[2],
            self.matrix_vector[3],
        ]
    }

    fn q_c(&self) -> F {
        self.constant
    }

    fn q_o(&self) -> F {
        F::one()
    }
}

#[derive(Debug, Clone)]
pub struct PartialRoundGate<F> {
    pub matrix_vector: Vec<F>,
    pub constant: F,
}

impl<F: PrimeField> Gate<F> for PartialRoundGate<F> {
    fn name(&self) -> &'static str {
        "Partial round, S-box and mix gate"
    }
    // Calculate w_1 + w_2 + w_3
    fn q_lc(&self) -> [F; jf_relation::constants::GATE_WIDTH] {
        [
            F::zero(),
            self.matrix_vector[1],
            self.matrix_vector[2],
            self.matrix_vector[3],
        ]
    }

    // Calculates w_0^5
    fn q_hash(&self) -> [F; GATE_WIDTH] {
        [self.matrix_vector[0], F::zero(), F::zero(), F::zero()]
    }

    fn q_c(&self) -> F {
        self.constant
    }

    fn q_o(&self) -> F {
        F::one()
    }
}

#[derive(Debug, Clone)]
pub struct PowerFiveGate;

impl<F: Field> Gate<F> for PowerFiveGate {
    fn name(&self) -> &'static str {
        "Power 5 Gate"
    }

    fn q_hash(&self) -> [F; GATE_WIDTH] {
        [F::one(), F::zero(), F::zero(), F::zero()]
    }

    fn q_o(&self) -> F {
        F::one()
    }
}
