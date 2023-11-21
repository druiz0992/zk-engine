use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, SWCurveConfig},
    CurveConfig, CurveGroup,
};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use jf_plonk::nightfall::{accumulation::accumulation_structs::PCSInstance, UnivariateIpaPCS};
use jf_primitives::{pcs::prelude::Commitment, rescue::RescueParameter};
use jf_relation::{
    errors::CircuitError,
    gadgets::ecc::{short_weierstrass::SWPoint, SWToTEConParam},
    Circuit, PlonkCircuit, Variable,
};
use jf_utils::field_switching;

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct SubTrees<F: PrimeField> {
    pub commitment_subtree: F,
    pub nullifier_subtree: F,
}

impl<F: PrimeField> SubTrees<F> {
    pub fn to_vec(&self) -> Vec<F> {
        vec![self.commitment_subtree, self.nullifier_subtree]
    }
    pub fn from_vec(array: Vec<F>) -> Self {
        Self {
            commitment_subtree: array[0],
            nullifier_subtree: array[1],
        }
    }
    pub fn to_vars(&self, mut circuit: PlonkCircuit<F>) -> Result<Vec<Variable>, CircuitError> {
        let vars = vec![
            circuit.create_variable(self.commitment_subtree)?,
            circuit.create_variable(self.nullifier_subtree)?,
        ];
        Ok(vars)
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct GlobalPublicInputs<F: PrimeField> {
    commitment_root: F,
    vk_root: F,
    initial_nullifier_root: F,
    initial_leaf_count: F,
    new_nullifier_root: F,
}

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct AccInstance<F: PrimeField> {
    pub comm: SWPoint<F>,
    pub eval: F,
    pub eval_point: F,
}
impl<F: PrimeField> AccInstance<F> {
    pub fn switch_field<T: PrimeField>(&self) -> AccInstance<T> {
        let switched_point_x = field_switching(&self.comm.0);
        let switched_point_y = field_switching(&self.comm.1);
        let switched_eval = field_switching(&self.eval);
        let switched_eval_point = field_switching(&self.eval_point);
        AccInstance {
            comm: SWPoint(switched_point_x, switched_point_y, self.comm.2),
            eval: switched_eval,
            eval_point: switched_eval_point,
        }
    }
    pub fn from_vec(array: Vec<F>) -> Self {
        let instance_sw = SWPoint(array[0], array[1], array[2] == F::one());
        let instance_value = array[3];
        let instance_point = array[4];
        Self {
            comm: instance_sw,
            eval: instance_value,
            eval_point: instance_point,
        }
    }

    pub fn field_switch_point<T: PrimeField>(&self) -> SWPoint<T> {
        let switched_point_x = field_switching(&self.comm.0);
        let switched_point_y = field_switching(&self.comm.1);
        SWPoint(switched_point_x, switched_point_y, self.comm.2)
    }
    pub fn field_switch_fields<T: PrimeField>(&self) -> (T, T) {
        (
            field_switching(&self.eval),
            field_switching(&self.eval_point),
        )
    }
    pub fn to_vec(&self) -> Vec<F> {
        let vars = vec![
            self.comm.0,
            self.comm.1,
            self.comm.2.into(),
            self.eval,
            self.eval_point,
        ];
        vars
    }
    pub fn to_vec_switch<T: PrimeField>(&self) -> Vec<T> {
        let vars = vec![
            field_switching(&self.comm.0),
            field_switching(&self.comm.1),
            self.comm.2.into(),
            field_switching(&self.eval),
            field_switching(&self.eval_point),
        ];
        vars
    }
    pub fn to_vars(&self, mut circuit: PlonkCircuit<F>) -> Result<Vec<Variable>, CircuitError> {
        let vars = vec![
            circuit.create_variable(self.comm.0)?,
            circuit.create_variable(self.comm.1)?,
            circuit.create_variable(self.comm.2.into())?,
            circuit.create_variable(self.eval)?,
            circuit.create_variable(self.eval_point)?,
        ];
        Ok(vars)
    }
    pub fn to_public_vars(
        &self,
        mut circuit: PlonkCircuit<F>,
    ) -> Result<Vec<Variable>, CircuitError> {
        let vars = vec![
            circuit.create_public_variable(self.comm.0)?,
            circuit.create_public_variable(self.comm.1)?,
            circuit.create_public_variable(self.comm.2.into())?,
            circuit.create_public_variable(self.eval)?,
            circuit.create_public_variable(self.eval_point)?,
        ];
        Ok(vars)
    }
}

impl<E, F> From<PCSInstance<UnivariateIpaPCS<E>>> for AccInstance<F>
where
    E: Pairing<BaseField = F, G1Affine = Affine<<<E as Pairing>::G1 as CurveGroup>::Config>>,
    <<E as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = E::BaseField>,
    <E as Pairing>::BaseField: RescueParameter + SWToTEConParam,

    F: PrimeField,
{
    fn from(value: PCSInstance<UnivariateIpaPCS<E>>) -> Self {
        let eval = field_switching(&value.value);
        let eval_point = field_switching(&value.point);
        Self {
            comm: value.comm.0.into(),
            eval,
            eval_point,
        }
    }
}

impl<E, F> Into<PCSInstance<UnivariateIpaPCS<E>>> for AccInstance<F>
where
    E: Pairing<BaseField = F, G1Affine = Affine<<<E as Pairing>::G1 as CurveGroup>::Config>>,
    <<E as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = E::BaseField>,
    <E as Pairing>::BaseField: RescueParameter + SWToTEConParam,

    F: PrimeField,
{
    fn into(self) -> PCSInstance<UnivariateIpaPCS<E>> {
        PCSInstance::new(
            Commitment(self.comm.into()),
            field_switching(&self.eval),
            field_switching(&self.eval_point),
        )
    }
}

impl<F: PrimeField> GlobalPublicInputs<F> {
    pub fn to_vec(&self) -> Vec<F> {
        vec![
            self.commitment_root,
            self.vk_root,
            self.initial_nullifier_root,
            self.initial_leaf_count,
            self.new_nullifier_root,
        ]
    }

    pub fn from_vec(array: Vec<F>) -> Self {
        Self {
            commitment_root: array[0],
            vk_root: array[1],
            initial_nullifier_root: array[2],
            initial_leaf_count: array[3],
            new_nullifier_root: array[4],
        }
    }

    pub fn to_vars(&self, mut circuit: PlonkCircuit<F>) -> Result<Vec<Variable>, CircuitError> {
        let vars = vec![
            circuit.create_variable(self.commitment_root)?,
            circuit.create_variable(self.vk_root)?,
            circuit.create_variable(self.initial_nullifier_root)?,
            circuit.create_variable(self.initial_leaf_count)?,
            circuit.create_variable(self.new_nullifier_root)?,
        ];
        Ok(vars)
    }
    pub fn to_public_vars(
        &self,
        mut circuit: PlonkCircuit<F>,
    ) -> Result<Vec<Variable>, CircuitError> {
        let vars = vec![
            circuit.create_public_variable(self.commitment_root)?,
            circuit.create_public_variable(self.vk_root)?,
            circuit.create_public_variable(self.initial_nullifier_root)?,
            circuit.create_public_variable(self.initial_leaf_count)?,
            circuit.create_public_variable(self.new_nullifier_root)?,
        ];
        Ok(vars)
    }
}
