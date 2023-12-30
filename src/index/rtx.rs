use super::*;

pub(crate) struct Rtx<'a>(pub(crate) redb::ReadTransaction<'a>);

impl Rtx<'_> {
  pub(crate) fn height(&self) -> Result<Option<Height>> {
    Ok(
      self
          .0
          .open_table(HEIGHT_TO_BLOCK_HASH)?
          .range(0..)?
          .rev()
          .next()
          .map(|result| match result {
              Ok((height, _hash)) => Some(Height(height.value())),
              Err(_) => None, // Handle the error as needed
          })
          .flatten(),
    )
  }

  pub(crate) fn block_count(&self) -> Result<u64> {
    Ok(
      self
          .0
          .open_table(HEIGHT_TO_BLOCK_HASH)?
          .range(0..)?
          .rev()
          .next()
          .map(|result| match result {
              Ok((height, _hash)) => Some(height.value() + 1),
              Err(_) => None, // Handle the error as needed
          })
          .flatten()
          .unwrap_or(0),
    )
  }
}
