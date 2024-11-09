use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::Zero;
use common::keypair::PublicKey;
use derivative::Derivative;
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
pub struct CircuitInputs<E>
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
impl<E> CircuitInputs<E>
where
    E: SWCurveConfig,
{
    pub fn new() -> Self {
        Self {
            token_values: Vec::new(),
            token_salts: Vec::new(),
            token_ids: Vec::new(),
            old_token_values: Vec::new(),
            old_token_salts: Vec::new(),
            old_token_ids: Vec::new(),
            commitment_tree_root: Vec::new(),
            membership_path: Vec::new(),
            membership_path_index: Vec::new(),
            recipients: Vec::new(),
            root_key: E::BaseField::zero(),
            ephemeral_key: E::BaseField::zero(),
        }
    }
    pub fn build(&self) -> Self {
        Self {
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
        }
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
}
