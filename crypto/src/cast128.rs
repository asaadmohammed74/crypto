use anyhow::{anyhow, Result};
use crate::cast128_sboxes::SBOXES;

#[derive(Default, Debug)]
pub struct Cast128 {
    key: Vec<u32>,
    short_key: bool,
    encrypt_num: i32,
    decrypt_num: i32,
    encrypt_iv: Vec<u8>,
    decrypt_iv: Vec<u8>,
}

impl Cast128 {
    const CAST5_BLOCK_SIZE: usize = 8;
    const CAST5_KEY_SIZE: usize = 16;
    const CAST5_EXT_KEY_SIZE: usize = 2 * Self::CAST5_KEY_SIZE;

    pub fn generate_key(&mut self, key: &[u8]) -> Result<()> {
        self.key = vec![0u32; Self::CAST5_EXT_KEY_SIZE];
        self.encrypt_iv = vec![0u8; Self::CAST5_BLOCK_SIZE];
        self.decrypt_iv = vec![0u8; Self::CAST5_BLOCK_SIZE];
        self.encrypt_num = 0;
        self.decrypt_num = 0;

        let mut length = key.len();

        if length == 0 {
            return Err(anyhow!("key cannot be empty"));
        }

        let mut small_x = [0u32; Self::CAST5_KEY_SIZE];
        let mut small_z = [0u32; Self::CAST5_KEY_SIZE];
        let mut cap_x = [0u32; 4];
        let mut cap_z = [0u32; 4];
        let mut cipher_key = [0u32; Self::CAST5_EXT_KEY_SIZE];

        if length > Self::CAST5_KEY_SIZE {
            length = Self::CAST5_KEY_SIZE;
        }

        for i in 0..length {
            small_x[i] = key[i].into();
        }

        self.short_key = length <= 10;

        cap_x[0] =
            (small_x[0x00] << 24) | (small_x[0x01] << 16) | (small_x[0x02] << 8) | small_x[0x03];
        cap_x[1] =
            (small_x[0x04] << 24) | (small_x[0x05] << 16) | (small_x[0x06] << 8) | small_x[0x07];
        cap_x[2] =
            (small_x[0x08] << 24) | (small_x[0x09] << 16) | (small_x[0x0A] << 8) | small_x[0x0B];
        cap_x[3] =
            (small_x[0x0C] << 24) | (small_x[0x0D] << 16) | (small_x[0x0E] << 8) | small_x[0x0F];

        let mut i = 0;

        loop {
            let l = cap_x[0]
                ^ SBOXES[4][small_x[13] as usize]
                ^ SBOXES[5][small_x[15] as usize]
                ^ SBOXES[6][small_x[12] as usize]
                ^ SBOXES[7][small_x[14] as usize]
                ^ SBOXES[6][small_x[8] as usize];
            Self::cast_exp(l, &mut cap_z, &mut small_z, 0);

            let l = cap_x[2]
                ^ SBOXES[4][small_z[0] as usize]
                ^ SBOXES[5][small_z[2] as usize]
                ^ SBOXES[6][small_z[1] as usize]
                ^ SBOXES[7][small_z[3] as usize]
                ^ SBOXES[7][small_x[10] as usize];
            Self::cast_exp(l, &mut cap_z, &mut small_z, 4);

            let l = cap_x[3]
                ^ SBOXES[4][small_z[7] as usize]
                ^ SBOXES[5][small_z[6] as usize]
                ^ SBOXES[6][small_z[5] as usize]
                ^ SBOXES[7][small_z[4] as usize]
                ^ SBOXES[4][small_x[9] as usize];
            Self::cast_exp(l, &mut cap_z, &mut small_z, 8);

            let l = cap_x[1]
                ^ SBOXES[4][small_z[10] as usize]
                ^ SBOXES[5][small_z[9] as usize]
                ^ SBOXES[6][small_z[11] as usize]
                ^ SBOXES[7][small_z[8] as usize]
                ^ SBOXES[5][small_x[11] as usize];
            Self::cast_exp(l, &mut cap_z, &mut small_z, 12);

            cipher_key[i] = SBOXES[4][small_z[8] as usize]
                ^ SBOXES[5][small_z[9] as usize]
                ^ SBOXES[6][small_z[7] as usize]
                ^ SBOXES[7][small_z[6] as usize]
                ^ SBOXES[4][small_z[2] as usize];
            cipher_key[i + 1] = SBOXES[4][small_z[10] as usize]
                ^ SBOXES[5][small_z[11] as usize]
                ^ SBOXES[6][small_z[5] as usize]
                ^ SBOXES[7][small_z[4] as usize]
                ^ SBOXES[5][small_z[6] as usize];
            cipher_key[i + 2] = SBOXES[4][small_z[12] as usize]
                ^ SBOXES[5][small_z[13] as usize]
                ^ SBOXES[6][small_z[3] as usize]
                ^ SBOXES[7][small_z[2] as usize]
                ^ SBOXES[6][small_z[9] as usize];
            cipher_key[i + 3] = SBOXES[4][small_z[14] as usize]
                ^ SBOXES[5][small_z[15] as usize]
                ^ SBOXES[6][small_z[1] as usize]
                ^ SBOXES[7][small_z[0] as usize]
                ^ SBOXES[7][small_z[12] as usize];

            let l = cap_z[2]
                ^ SBOXES[4][small_z[5] as usize]
                ^ SBOXES[5][small_z[7] as usize]
                ^ SBOXES[6][small_z[4] as usize]
                ^ SBOXES[7][small_z[6] as usize]
                ^ SBOXES[6][small_z[0] as usize];
            Self::cast_exp(l, &mut cap_x, &mut small_x, 0);
            let l = cap_z[0]
                ^ SBOXES[4][small_x[0] as usize]
                ^ SBOXES[5][small_x[2] as usize]
                ^ SBOXES[6][small_x[1] as usize]
                ^ SBOXES[7][small_x[3] as usize]
                ^ SBOXES[7][small_z[2] as usize];
            Self::cast_exp(l, &mut cap_x, &mut small_x, 4);
            let l = cap_z[1]
                ^ SBOXES[4][small_x[7] as usize]
                ^ SBOXES[5][small_x[6] as usize]
                ^ SBOXES[6][small_x[5] as usize]
                ^ SBOXES[7][small_x[4] as usize]
                ^ SBOXES[4][small_z[1] as usize];
            Self::cast_exp(l, &mut cap_x, &mut small_x, 8);
            let l = cap_z[3]
                ^ SBOXES[4][small_x[10] as usize]
                ^ SBOXES[5][small_x[9] as usize]
                ^ SBOXES[6][small_x[11] as usize]
                ^ SBOXES[7][small_x[8] as usize]
                ^ SBOXES[5][small_z[3] as usize];
            Self::cast_exp(l, &mut cap_x, &mut small_x, 12);

            cipher_key[i + 4] = SBOXES[4][small_x[3] as usize]
                ^ SBOXES[5][small_x[2] as usize]
                ^ SBOXES[6][small_x[12] as usize]
                ^ SBOXES[7][small_x[13] as usize]
                ^ SBOXES[4][small_x[8] as usize];
            cipher_key[i + 5] = SBOXES[4][small_x[1] as usize]
                ^ SBOXES[5][small_x[0] as usize]
                ^ SBOXES[6][small_x[14] as usize]
                ^ SBOXES[7][small_x[15] as usize]
                ^ SBOXES[5][small_x[13] as usize];
            cipher_key[i + 6] = SBOXES[4][small_x[7] as usize]
                ^ SBOXES[5][small_x[6] as usize]
                ^ SBOXES[6][small_x[8] as usize]
                ^ SBOXES[7][small_x[9] as usize]
                ^ SBOXES[6][small_x[3] as usize];
            cipher_key[i + 7] = SBOXES[4][small_x[5] as usize]
                ^ SBOXES[5][small_x[4] as usize]
                ^ SBOXES[6][small_x[10] as usize]
                ^ SBOXES[7][small_x[11] as usize]
                ^ SBOXES[7][small_x[7] as usize];

            cipher_key[i + 4] = SBOXES[4][small_x[3] as usize]
                ^ SBOXES[5][small_x[2] as usize]
                ^ SBOXES[6][small_x[12] as usize]
                ^ SBOXES[7][small_x[13] as usize]
                ^ SBOXES[4][small_x[8] as usize];
            cipher_key[i + 5] = SBOXES[4][small_x[1] as usize]
                ^ SBOXES[5][small_x[0] as usize]
                ^ SBOXES[6][small_x[14] as usize]
                ^ SBOXES[7][small_x[15] as usize]
                ^ SBOXES[5][small_x[13] as usize];
            cipher_key[i + 6] = SBOXES[4][small_x[7] as usize]
                ^ SBOXES[5][small_x[6] as usize]
                ^ SBOXES[6][small_x[8] as usize]
                ^ SBOXES[7][small_x[9] as usize]
                ^ SBOXES[6][small_x[3] as usize];
            cipher_key[i + 7] = SBOXES[4][small_x[5] as usize]
                ^ SBOXES[5][small_x[4] as usize]
                ^ SBOXES[6][small_x[10] as usize]
                ^ SBOXES[7][small_x[11] as usize]
                ^ SBOXES[7][small_x[7] as usize];

            let l = cap_x[0]
                ^ SBOXES[4][small_x[13] as usize]
                ^ SBOXES[5][small_x[15] as usize]
                ^ SBOXES[6][small_x[12] as usize]
                ^ SBOXES[7][small_x[14] as usize]
                ^ SBOXES[6][small_x[8] as usize];
            Self::cast_exp(l, &mut cap_z, &mut small_z, 0);
            let l = cap_x[2]
                ^ SBOXES[4][small_z[0] as usize]
                ^ SBOXES[5][small_z[2] as usize]
                ^ SBOXES[6][small_z[1] as usize]
                ^ SBOXES[7][small_z[3] as usize]
                ^ SBOXES[7][small_x[10] as usize];
            Self::cast_exp(l, &mut cap_z, &mut small_z, 4);
            let l = cap_x[3]
                ^ SBOXES[4][small_z[7] as usize]
                ^ SBOXES[5][small_z[6] as usize]
                ^ SBOXES[6][small_z[5] as usize]
                ^ SBOXES[7][small_z[4] as usize]
                ^ SBOXES[4][small_x[9] as usize];
            Self::cast_exp(l, &mut cap_z, &mut small_z, 8);
            let l = cap_x[1]
                ^ SBOXES[4][small_z[10] as usize]
                ^ SBOXES[5][small_z[9] as usize]
                ^ SBOXES[6][small_z[11] as usize]
                ^ SBOXES[7][small_z[8] as usize]
                ^ SBOXES[5][small_x[11] as usize];
            Self::cast_exp(l, &mut cap_z, &mut small_z, 12);

            cipher_key[i + 8] = SBOXES[4][small_z[3] as usize]
                ^ SBOXES[5][small_z[2] as usize]
                ^ SBOXES[6][small_z[12] as usize]
                ^ SBOXES[7][small_z[13] as usize]
                ^ SBOXES[4][small_z[9] as usize];
            cipher_key[i + 9] = SBOXES[4][small_z[1] as usize]
                ^ SBOXES[5][small_z[0] as usize]
                ^ SBOXES[6][small_z[14] as usize]
                ^ SBOXES[7][small_z[15] as usize]
                ^ SBOXES[5][small_z[12] as usize];
            cipher_key[i + 10] = SBOXES[4][small_z[7] as usize]
                ^ SBOXES[5][small_z[6] as usize]
                ^ SBOXES[6][small_z[8] as usize]
                ^ SBOXES[7][small_z[9] as usize]
                ^ SBOXES[6][small_z[2] as usize];
            cipher_key[i + 11] = SBOXES[4][small_z[5] as usize]
                ^ SBOXES[5][small_z[4] as usize]
                ^ SBOXES[6][small_z[10] as usize]
                ^ SBOXES[7][small_z[11] as usize]
                ^ SBOXES[7][small_z[6] as usize];

            let l = cap_z[2]
                ^ SBOXES[4][small_z[5] as usize]
                ^ SBOXES[5][small_z[7] as usize]
                ^ SBOXES[6][small_z[4] as usize]
                ^ SBOXES[7][small_z[6] as usize]
                ^ SBOXES[6][small_z[0] as usize];
            Self::cast_exp(l, &mut cap_x, &mut small_x, 0);
            let l = cap_z[0]
                ^ SBOXES[4][small_x[0] as usize]
                ^ SBOXES[5][small_x[2] as usize]
                ^ SBOXES[6][small_x[1] as usize]
                ^ SBOXES[7][small_x[3] as usize]
                ^ SBOXES[7][small_z[2] as usize];
            Self::cast_exp(l, &mut cap_x, &mut small_x, 4);
            let l = cap_z[1]
                ^ SBOXES[4][small_x[7] as usize]
                ^ SBOXES[5][small_x[6] as usize]
                ^ SBOXES[6][small_x[5] as usize]
                ^ SBOXES[7][small_x[4] as usize]
                ^ SBOXES[4][small_z[1] as usize];
            Self::cast_exp(l, &mut cap_x, &mut small_x, 8);
            let l = cap_z[3]
                ^ SBOXES[4][small_x[10] as usize]
                ^ SBOXES[5][small_x[9] as usize]
                ^ SBOXES[6][small_x[11] as usize]
                ^ SBOXES[7][small_x[8] as usize]
                ^ SBOXES[5][small_z[3] as usize];
            Self::cast_exp(l, &mut cap_x, &mut small_x, 12);

            cipher_key[i + 12] = SBOXES[4][small_x[8] as usize]
                ^ SBOXES[5][small_x[9] as usize]
                ^ SBOXES[6][small_x[7] as usize]
                ^ SBOXES[7][small_x[6] as usize]
                ^ SBOXES[4][small_x[3] as usize];
            cipher_key[i + 13] = SBOXES[4][small_x[10] as usize]
                ^ SBOXES[5][small_x[11] as usize]
                ^ SBOXES[6][small_x[5] as usize]
                ^ SBOXES[7][small_x[4] as usize]
                ^ SBOXES[5][small_x[7] as usize];
            cipher_key[i + 14] = SBOXES[4][small_x[12] as usize]
                ^ SBOXES[5][small_x[13] as usize]
                ^ SBOXES[6][small_x[3] as usize]
                ^ SBOXES[7][small_x[2] as usize]
                ^ SBOXES[6][small_x[8] as usize];
            cipher_key[i + 15] = SBOXES[4][small_x[14] as usize]
                ^ SBOXES[5][small_x[15] as usize]
                ^ SBOXES[6][small_x[1] as usize]
                ^ SBOXES[7][small_x[0] as usize]
                ^ SBOXES[7][small_x[13] as usize];

            if i != 0 {
                break;
            }

            i += Self::CAST5_KEY_SIZE;
        }

        for i in 0..Self::CAST5_KEY_SIZE {
            self.key[i * 2] = cipher_key[i];
            self.key[i * 2 + 1] =
                ((cipher_key[i + Self::CAST5_KEY_SIZE]) + Self::CAST5_KEY_SIZE as u32) & 0x1F;
        }

        Ok(())
    }

    fn cast_exp(l: u32, cap_a: &mut [u32], a: &mut [u32], n: u32) {
        let n = n as usize;

        cap_a[n / 4] = l;
        a[n + 3] = l & 0xFF;
        a[n + 2] = l.wrapping_shr(8) & 0xFF;
        a[n + 1] = l.wrapping_shr(16) & 0xFF;
        a[n] = l.wrapping_shr(24) & 0xFF;
    }
}
