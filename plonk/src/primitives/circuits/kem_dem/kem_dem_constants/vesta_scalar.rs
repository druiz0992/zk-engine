use curves::vesta::Fr;

use crate::primitives::circuits::kem_dem::KemDemParams;

// TODO these params need to be updated for the field Fr, currently modded by field baby  jubjub
impl KemDemParams for Fr {
    /// DOMAIN_KEM = Fq_bjj(SHA256('nightfall-kem')) -> Little_endian
    const DOMAIN_KEM: &'static [u8; super::FIELD_ELEMENT_BYTES] = super::DOMAIN_KEM;
    // DOMAIN_KEM = field_bjj(SHA256('nightfall-dem')) -> Little_endian
    const DOMAIN_DEM: &'static [u8; super::FIELD_ELEMENT_BYTES] = super::DOMAIN_DEM;
}
