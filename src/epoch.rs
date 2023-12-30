use super::*;

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, PartialOrd)]
pub(crate) struct Epoch(pub(crate) u64);

impl Epoch {
  pub(crate) const STARTING_SATS: [Sat; 8] = [
    Sat(0 * COIN_VALUE as u128),
    Sat(100000000000 * COIN_VALUE as u128),
    Sat(122500000000 * COIN_VALUE as u128),
    Sat(136250000000 * COIN_VALUE as u128),
    Sat(148750000000 * COIN_VALUE as u128),
    Sat(155000000000 * COIN_VALUE as u128),
    Sat(158125000000 * COIN_VALUE as u128),
    Sat(159687500000 * COIN_VALUE as u128),
  ];

  pub(crate) fn subsidy(self) -> u64 {
    match self.0 {
      0 => 1_000_000 * COIN_VALUE,
      1 => 500_000 * COIN_VALUE,
      2 => 250_000 * COIN_VALUE,
      3 => 125_000 * COIN_VALUE,
      4 => 62_500 * COIN_VALUE,
      5 => 31_250 * COIN_VALUE,
      6 => 15_625 * COIN_VALUE,
      7 => 10_000 * COIN_VALUE,
      _ => panic!("bad epoch"),
    }
  }

  pub(crate) fn starting_sat(self) -> Sat {
    *Self::STARTING_SATS
      .get(usize::try_from(self.0).unwrap())
      .unwrap_or_else(|| Self::STARTING_SATS.last().unwrap())
  }

  pub(crate) fn starting_height(self) -> Height {
    match self.0 {
      0 => Height(0),
      1 => Height(100_000),
      2 => Height(145_000),
      3 => Height(200_000),
      4 => Height(300_000),
      5 => Height(400_000),
      6 => Height(500_000),
      7 => Height(600_000),
      _ => panic!("bad epoch"),
    }
  }
}

impl PartialEq<u64> for Epoch {
  fn eq(&self, other: &u64) -> bool {
    self.0 == *other
  }
}

impl From<Sat> for Epoch {
  fn from(sat: Sat) -> Self {
    if sat < Self::STARTING_SATS[1] {
      Epoch(0)
    } else if sat < Self::STARTING_SATS[2] {
      Epoch(1)
    } else if sat < Self::STARTING_SATS[3] {
      Epoch(2)
    } else if sat < Self::STARTING_SATS[4] {
      Epoch(3)
    } else if sat < Self::STARTING_SATS[5] {
      Epoch(4)
    } else if sat < Self::STARTING_SATS[6] {
      Epoch(5)
    } else if sat < Self::STARTING_SATS[7] {
      Epoch(6)
    } else {
      Epoch(7)
    }
  }
}

impl From<Height> for Epoch {
  fn from(height: Height) -> Self {
    if height.0 < 100_000 {
      Epoch(0)
    } else if height.0 < 145_000 {
      Epoch(1)
    } else if height.0 < 200_000 {
      Epoch(2)
    } else if height.0 < 300_000 {
      Epoch(3)
    } else if height.0 < 400_000 {
      Epoch(4)
    } else if height.0 < 500_000 {
      Epoch(5)
    } else if height.0 < 600_000 {
      Epoch(6)
    } else {
      Epoch(7)
    }
  }
}

#[cfg(test)]
mod tests {
  use super::super::*;

  #[test]
  fn starting_sat() {
    assert_eq!(Epoch(0).starting_sat(), 0);
  }

  #[test]
  fn subsidy() {
    assert_eq!(Epoch(0).subsidy(), 1_000_000 * COIN_VALUE);
    assert_eq!(Epoch(1).subsidy(), 500_000 * COIN_VALUE);
    // assert_eq!(Epoch(32).subsidy(), 1);
    // assert_eq!(Epoch(33).subsidy(), 0);
  }

  #[test]
  fn starting_height() {
    assert_eq!(Epoch(0).starting_height(), 0);
    assert_eq!(Epoch(1).starting_height(), 100_000);
    assert_eq!(Epoch(2).starting_height(), 145_000);
  }

  #[test]
  fn from_height() {
    assert_eq!(Epoch::from(Height(0)), 0);
    assert_eq!(Epoch::from(Height(100_000)), 1);
    assert_eq!(Epoch::from(Height(150_000)), 2);
    assert_eq!(Epoch::from(Height(200_000)), 3);
  }

  #[test]
  fn from_sat() {
    for (epoch, starting_sat) in Epoch::STARTING_SATS.into_iter().enumerate() {
      if epoch > 0 {
        assert_eq!(
          Epoch::from(Sat(starting_sat.n() - 1)),
          Epoch(epoch as u64 - 1)
        );
      }
      assert_eq!(Epoch::from(starting_sat), Epoch(epoch as u64));
      assert_eq!(Epoch::from(starting_sat + 1), Epoch(epoch as u64));
    }
    assert_eq!(Epoch::from(Sat(0)), 0);
    assert_eq!(Epoch::from(Sat(1)), 0);
    assert_eq!(Epoch::from(Epoch(1).starting_sat()), 1);
    assert_eq!(Epoch::from(Epoch(1).starting_sat() + 1), 1);
    // assert_eq!(Epoch::from(Sat(u128::max_value())), 33);
  }

  #[test]
  fn eq() {
    assert_eq!(Epoch(0), 0);
    assert_eq!(Epoch(100), 100);
  }
}
