use ark_ed_on_bn254::Fq;

use crate::primitives::circuits::kem_dem::KemDemParams;

impl KemDemParams for Fq {
    /// DOMAIN_KEM = Fq(SHA256('nightfall-kem')) -> Little_endian
    const DOMAIN_KEM: &'static [u8; super::FIELD_ELEMENT_BYTES] = super::DOMAIN_KEM;
    // DOMAIN_KEM = field(SHA256('nightfall-dem')) -> Little_endian
    const DOMAIN_DEM: &'static [u8; super::FIELD_ELEMENT_BYTES] = super::DOMAIN_DEM;
}
