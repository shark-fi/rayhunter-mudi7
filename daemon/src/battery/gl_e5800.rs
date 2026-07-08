use std::path::Path;

use crate::{
    battery::{BatteryState, get_level_from_percentage_file, is_plugged_in_from_file},
    error::RayhunterError,
};

// GL-E5800 (Mudi 7): CellWise cw221X fuel gauge + charger, both on i2c-2.
const BATTERY_LEVEL_FILE: &str = "/sys/class/power_supply/cw221X-bat/capacity";
const PLUGGED_IN_STATE_FILE: &str = "/sys/class/power_supply/charger/online";

pub async fn get_battery_state() -> Result<BatteryState, RayhunterError> {
    Ok(BatteryState {
        level: get_level_from_percentage_file(Path::new(BATTERY_LEVEL_FILE)).await?,
        is_plugged_in: is_plugged_in_from_file(Path::new(PLUGGED_IN_STATE_FILE)).await?,
    })
}
