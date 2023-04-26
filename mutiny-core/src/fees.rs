use crate::indexed_db::MutinyStorage;
use lightning::chain::chaininterface::{
    ConfirmationTarget, FeeEstimator, FEERATE_FLOOR_SATS_PER_KW,
};
use log::trace;

#[derive(Clone)]
pub struct MutinyFeeEstimator {
    storage: MutinyStorage,
}

impl MutinyFeeEstimator {
    pub fn new(storage: MutinyStorage) -> MutinyFeeEstimator {
        MutinyFeeEstimator { storage }
    }
}

impl FeeEstimator for MutinyFeeEstimator {
    fn get_est_sat_per_1000_weight(&self, confirmation_target: ConfirmationTarget) -> u32 {
        let num_blocks = num_blocks_from_conf_target(confirmation_target);
        let fallback_fee = fallback_fee_from_conf_target(confirmation_target);

        match self.storage.get_fee_estimates() {
            Err(_) | Ok(None) => fallback_fee,
            Ok(Some(estimates)) => {
                let found = estimates.get(&num_blocks.to_string());
                match found {
                    Some(num) => {
                        trace!("Got fee rate from saved cache!");
                        let sats_vbyte = num.to_owned();
                        // convert to sats per kw
                        let fee_rate = sats_vbyte * 250.0;

                        // return the fee rate, but make sure it's not lower than the floor
                        (fee_rate as u32).max(FEERATE_FLOOR_SATS_PER_KW)
                    }
                    None => fallback_fee,
                }
            }
        }
    }
}

fn num_blocks_from_conf_target(confirmation_target: ConfirmationTarget) -> usize {
    match confirmation_target {
        ConfirmationTarget::Background => 12,
        ConfirmationTarget::Normal => 6,
        ConfirmationTarget::HighPriority => 3,
    }
}

fn fallback_fee_from_conf_target(confirmation_target: ConfirmationTarget) -> u32 {
    match confirmation_target {
        ConfirmationTarget::Background => FEERATE_FLOOR_SATS_PER_KW,
        ConfirmationTarget::Normal => 2000,
        ConfirmationTarget::HighPriority => 5000,
    }
}
