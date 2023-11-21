mod keypair;
mod transaction;
pub mod primitives {

    pub type Curve = curves::vesta::VestaConfig;
    pub type Fr = curves::vesta::Fr;
    pub type Fq = curves::vesta::Fq;

    pub type ECurve = curves::pallas::PallasConfig;
    pub type EFr = curves::pallas::Fr;
    pub type EFq = curves::pallas::Fq;

    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
    use num_bigint::BigUint;
    use num_traits::Num;

    pub fn ark_se<S, A: CanonicalSerialize>(a: &A, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = vec![];
        a.serialize_with_mode(&mut bytes, Compress::Yes)
            .map_err(serde::ser::Error::custom)?;
        let hex_s = BigUint::from_bytes_le(bytes.as_slice()).to_str_radix(16);
        s.serialize_str(&hex_s)
    }

    pub fn ark_de<'de, D, A: CanonicalDeserialize>(data: D) -> Result<A, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let hex_s: String = serde::de::Deserialize::deserialize(data)?;
        ark_std::println!("hex_s: {}", hex_s);
        let s = BigUint::from_str_radix(&hex_s, 16).map_err(serde::de::Error::custom)?;
        ark_std::println!("s: {}", s);
        let mut bytes = s.to_bytes_le();
        bytes.resize(33, 0); // Magic!

        let a = A::deserialize_with_mode(bytes.as_slice(), Compress::Yes, Validate::No);
        a.map_err(serde::de::Error::custom)
    }
}
pub use self::keypair::*;
pub use self::transaction::*;
pub use primitives::*;
