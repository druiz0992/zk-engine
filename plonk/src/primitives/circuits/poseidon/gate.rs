use ark_ff::{Field, PrimeField};
use jf_relation::{constants::GATE_WIDTH, gates::Gate};

#[derive(Debug, Clone)]
pub struct Power5NonLinearGate<F> {
    pub matrix_vector: Vec<F>,
    pub constant: F,
}

impl<F: PrimeField> Gate<F> for Power5NonLinearGate<F> {
    fn name(&self) -> &'static str {
        "Full round gate"
    }

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
pub struct Power5NoConstantGate<F> {
    pub matrix_vector: Vec<F>,
}

impl<F: PrimeField> Gate<F> for Power5NoConstantGate<F> {
    fn name(&self) -> &'static str {
        "Full round no constant gate"
    }

    fn q_hash(&self) -> [F; GATE_WIDTH] {
        [
            self.matrix_vector[0],
            self.matrix_vector[1],
            self.matrix_vector[2],
            self.matrix_vector[3],
        ]
    }

    fn q_o(&self) -> F {
        F::one()
    }
}

#[derive(Debug, Clone)]
pub struct NonFullRoundGate<F> {
    pub matrix_vector: Vec<F>,
    pub constant: F,
}

impl<F: PrimeField> Gate<F> for NonFullRoundGate<F> {
    fn name(&self) -> &'static str {
        "Partial round gate"
    }
    fn q_lc(&self) -> [F; jf_relation::constants::GATE_WIDTH] {
        [
            F::zero(),
            self.matrix_vector[1],
            self.matrix_vector[2],
            self.matrix_vector[3],
        ]
    }

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
pub struct NonFullRoundNoConstantGate<F> {
    pub matrix_vector: Vec<F>,
}

impl<F: PrimeField> Gate<F> for NonFullRoundNoConstantGate<F> {
    fn name(&self) -> &'static str {
        "Partial round no constant gate"
    }
    fn q_lc(&self) -> [F; jf_relation::constants::GATE_WIDTH] {
        [
            self.matrix_vector[0],
            self.matrix_vector[1],
            self.matrix_vector[2],
            self.matrix_vector[3],
        ]
    }

    fn q_o(&self) -> F {
        F::one()
    }
}

#[derive(Debug, Clone)]
pub struct CheckCompressedSecretsGate;

impl<F: Field> Gate<F> for CheckCompressedSecretsGate {
    fn name(&self) -> &'static str {
        "Check compressed secrets are zero gate"
    }

    fn q_lc(&self) -> [F; GATE_WIDTH] {
        [F::one(), F::one(), F::zero(), F::zero()]
    }

    fn q_mul(&self) -> [F; jf_relation::constants::N_MUL_SELECTORS] {
        [F::one(), F::zero()]
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
