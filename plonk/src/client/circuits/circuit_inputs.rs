use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::Zero;
use common::keypair::PublicKey;
use derivative::Derivative;
use jf_relation::errors::CircuitError;
use trees::MembershipPath;

#[derive(Derivative, Default, Debug)]
#[derivative(
    Clone(bound = "E: SWCurveConfig"),
    PartialEq(bound = "E: SWCurveConfig"),
    Eq(bound = "E: SWCurveConfig"),
    Hash(bound = "E: SWCurveConfig")
)]

// N: number of nullifiers
// C: number of commitments
// D: depth of the merkle tree
pub struct CircuitInputs<E, const C: usize, const N: usize, const D: usize>
where
    E: SWCurveConfig,
{
    pub token_values: Vec<E::BaseField>,
    pub token_salts: Vec<E::BaseField>,
    pub token_ids: Vec<E::BaseField>,
    pub old_token_values: Vec<E::BaseField>,
    pub old_token_salts: Vec<E::BaseField>,
    pub old_token_ids: Vec<E::BaseField>,
    pub commitment_tree_root: Vec<E::BaseField>,
    pub membership_path: Vec<MembershipPath<E::BaseField>>,
    pub membership_path_index: Vec<E::BaseField>,
    pub recipients: Vec<PublicKey<E>>,
    pub root_key: E::BaseField,
    pub ephemeral_key: E::BaseField,
}

/*
N=1, D=1
Mint:
    token_values: [V::ScalarField; C],
    token_salts: [V::ScalarField; C],
    token_ids: [V::ScalarField; C],
    recipients: [Affine<P>; C],

Transfer:
    token_values: [P::ScalarField; C],
    token_salts: [P::ScalarField; C], // The first one of this must be the old_commitment_leaf_index
    token_ids: P::ScalarField,
    old_token_values: [P::ScalarField; N],
    old_token_salts: [P::ScalarField; N],
    commitment_tree_root: [P::ScalarField; N],
    membership_path: [[P::ScalarField; D]; N],
    membership_path_index: [P::ScalarField; N],
    recipients: Affine<E>,
    root_key: P::ScalarField,
    ephemeral_key: P::ScalarField,

Swap:
    token_values: P::ScalarField,
    token_salts: P::ScalarField,
    token_ids: P::ScalarField,
    old_token_values: P::ScalarField,
    old_token_salts: P::ScalarField,
    old_token_ids: P::ScalarField,
    commitment_tree_root: P::ScalarField,
    membership_path: [P::ScalarField; D],
    membership_path_index: P::ScalarField,
    recipients: Affine<E>,
    root_key: P::ScalarField,
    ephemeral_key: P::ScalarField,

*/
impl<E, const C: usize, const N: usize, const D: usize> CircuitInputs<E, C, N, D>
where
    E: SWCurveConfig,
{
    pub fn new() -> Self {
        Self {
            token_values: Vec::with_capacity(C),
            token_salts: Vec::with_capacity(C),
            token_ids: Vec::with_capacity(C),
            old_token_values: Vec::with_capacity(N),
            old_token_salts: Vec::with_capacity(N),
            old_token_ids: Vec::with_capacity(N),
            commitment_tree_root: Vec::with_capacity(N),
            membership_path: Vec::with_capacity(N),
            membership_path_index: Vec::with_capacity(N),
            recipients: Vec::with_capacity(1),
            root_key: E::BaseField::zero(),
            ephemeral_key: E::BaseField::zero(),
        }
    }
    pub fn build(&self) -> Result<Self, CircuitError> {
        self.check_params()?;
        Ok(Self {
            token_values: self.token_values.clone(),
            token_salts: self.token_salts.clone(),
            token_ids: self.token_ids.clone(),
            old_token_values: self.old_token_values.clone(),
            old_token_salts: self.old_token_salts.clone(),
            old_token_ids: self.old_token_ids.clone(),
            commitment_tree_root: self.commitment_tree_root.clone(),
            membership_path: self.membership_path.clone(),
            membership_path_index: self.membership_path_index.clone(),
            recipients: self.recipients.clone(),
            root_key: self.root_key,
            ephemeral_key: self.ephemeral_key,
        })
    }
    pub fn add_token_values(&mut self, token_value: Vec<E::BaseField>) -> &mut Self {
        self.token_values = token_value;
        self
    }
    pub fn add_token_salts(&mut self, salts: Vec<E::BaseField>) -> &mut Self {
        self.token_salts = salts;
        self
    }
    pub fn add_token_ids(&mut self, token_id: Vec<E::BaseField>) -> &mut Self {
        self.token_ids = token_id;
        self
    }
    pub fn add_old_token_values(&mut self, old_token_values: Vec<E::BaseField>) -> &mut Self {
        self.old_token_values = old_token_values;
        self
    }
    pub fn add_old_token_salts(&mut self, old_token_salts: Vec<E::BaseField>) -> &mut Self {
        self.old_token_salts = old_token_salts;
        self
    }
    pub fn add_old_token_ids(&mut self, old_token_ids: Vec<E::BaseField>) -> &mut Self {
        self.old_token_ids = old_token_ids;
        self
    }
    pub fn add_commitment_tree_root(&mut self, root: Vec<E::BaseField>) -> &mut Self {
        self.commitment_tree_root = root;
        self
    }
    pub fn add_membership_path(
        &mut self,
        membership_path: Vec<MembershipPath<E::BaseField>>,
    ) -> &mut Self {
        self.membership_path = membership_path;
        self
    }
    pub fn add_membership_path_index(
        &mut self,
        membership_path_index: Vec<E::BaseField>,
    ) -> &mut Self {
        self.membership_path_index = membership_path_index;
        self
    }
    pub fn add_recipients(&mut self, recipients: Vec<PublicKey<E>>) -> &mut Self {
        self.recipients = recipients;
        self
    }
    pub fn add_ephemeral_key(&mut self, ephemeral_key: E::BaseField) -> &mut Self {
        self.ephemeral_key = ephemeral_key;
        self
    }
    pub fn add_root_key(&mut self, root_key: E::BaseField) -> &mut Self {
        self.root_key = root_key;
        self
    }

    fn check_params(&self) -> Result<(), CircuitError> {
        fn check_length(
            field_name: &str,
            actual_len: usize,
            expected_len: usize,
        ) -> Result<(), CircuitError> {
            if actual_len != expected_len {
                Err(CircuitError::ParameterError(format!(
                    "Incorrect length for {field_name}. Expected {expected_len}, Obtained {actual_len}"
                )))
            } else {
                Ok(())
            }
        }

        // Check all fields with their respective expected lengths
        check_length("token_values", self.token_values.len(), C)?;
        check_length("token_salts", self.token_salts.len(), C)?;
        //check_length("token_ids", self.token_ids.len(), C)?;
        check_length("old_token_values", self.old_token_values.len(), N)?;
        check_length("old_token_salts", self.old_token_salts.len(), N)?;
        //check_length("old_token_ids", self.old_token_ids.len(), N)?;
        check_length("commitment_tree_root", self.commitment_tree_root.len(), N)?;
        check_length("membership_path_index", self.membership_path_index.len(), N)?;
        check_length("membership_path", self.membership_path.len(), N)?;

        if !self
            .membership_path
            .iter()
            .all(|inner_vec| inner_vec.path_len() == D)
        {
            return Err(CircuitError::ParameterError(format!(
                "Incorrect length for membership_path elements. Expected {D}",
            )));
        }

        Ok(())
    }
}
